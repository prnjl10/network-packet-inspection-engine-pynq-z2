"""
packet_inspector.py
===================
PYNQ overlay driver for the line-rate network packet inspection engine
(packet_inspector_top + AXI-DMA on a PYNQ-Z2 / xc7z020).

Wraps the inspector's AXI-Lite register interface and the AXI-DMA into a
single clean Python API, so application code never touches raw offsets.

Usage
-----
    from pynq import Overlay
    from packet_inspector import PacketInspector, build_frame

    ol = Overlay("packet_inspector.bit")     # .hwh must sit next to the .bit
    pi = PacketInspector(ol)

    pi.program_rule(0, protocol=6, action=PacketInspector.ACT_DROP)  # drop all TCP
    pi.send_packet(build_frame())            # push a TCP SYN frame through
    print(pi.counters())
    print(pi.drain_event())

Hardware register map (AXI-Lite slave, base auto-assigned by PYNQ):
    0x000 VERSION      (RO, 0xDEADBEEF)
    0x004 STATUS       (RO, {overflow, full, empty, has_events} in bits [3:0])
    0x008 PACKET_COUNT (RO)
    0x00C DROP_COUNT   (RO)
    0x010 FIFO_LEVEL   (RO)
    0x020..0x03C RULE_HIT_COUNT[0..7]
    0x040..0x048 ANOMALY_HIT_COUNT[0..2]
    0x050..0x060 EVENT_WORD[0..4]   (read of 0x060 auto-pops the FIFO)
    0x080..0x0FC RULE_TABLE         (8 rules x 4 words, 16 bytes each)
"""

import struct
import numpy as np
from pynq import allocate


# ---------------------------------------------------------------------------
# Frame builder (no scapy dependency -> works on an offline/direct-connected board)
# ---------------------------------------------------------------------------
def build_frame(src_ip="10.0.0.1", dst_ip="10.0.0.2",
                src_port=1234, dst_port=80,
                protocol=6, tcp_flags=0x02, payload=b""):
    """Build a raw Ethernet/IPv4/(TCP|UDP) frame as bytes.

    protocol : 6 = TCP, 17 = UDP (others -> bare IP, no L4 header).
    tcp_flags: bit0=FIN, bit1=SYN, bit2=RST, ... (0x02 = SYN).
    The IP total_length is computed so the engine's ip_len_mismatch
    anomaly does not fire spuriously.
    """
    # Ethernet header (14 bytes): dst MAC + src MAC + ethertype (IPv4)
    eth = bytes.fromhex("001122334455") + bytes.fromhex("66778899aabb") \
        + struct.pack(">H", 0x0800)

    # Layer 4
    if protocol == 6:        # TCP (20-byte header)
        l4 = struct.pack(">HHIIBBHHH", src_port, dst_port, 0, 0,
                         (5 << 4), tcp_flags, 8192, 0, 0)
    elif protocol == 17:     # UDP (8-byte header)
        l4 = struct.pack(">HHHH", src_port, dst_port, 8 + len(payload), 0)
    else:
        l4 = b""
    l4 += payload

    # IPv4 header (20 bytes); checksum left 0 (engine does not verify it)
    total_len = 20 + len(l4)
    sip = bytes(int(x) for x in src_ip.split("."))
    dip = bytes(int(x) for x in dst_ip.split("."))
    ip = struct.pack(">BBHHHBBH",
                     0x45, 0, total_len, 0, 0, 64, protocol, 0) + sip + dip

    return eth + ip + l4


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
class PacketInspector:
    """Driver for the packet_inspector_top IP and its companion AXI-DMA."""

    # Register offsets
    VERSION, STATUS, PKT_CNT, DROP_CNT, FIFO_LVL = 0x000, 0x004, 0x008, 0x00C, 0x010
    RULE_HIT_BASE    = 0x020      # + i*4, i in 0..7
    ANOMALY_HIT_BASE = 0x040      # + j*4, j in 0..2
    RULE_BASE        = 0x080      # rule i at 0x080 + i*0x10

    # Rule action codes (rule_entry_t.action)
    ACT_ACCEPT, ACT_DROP, ACT_FLAG = 0, 1, 2

    NUM_RULES = 8

    def __init__(self, overlay):
        self.ip  = overlay.packet_inspector_top_0   # AXI-Lite register interface
        self.dma = overlay.axi_dma_0                # data mover

    # -- simple reads -------------------------------------------------------
    def version(self):       return self.ip.read(self.VERSION)
    def packet_count(self):  return self.ip.read(self.PKT_CNT)
    def drop_count(self):    return self.ip.read(self.DROP_CNT)
    def fifo_level(self):    return self.ip.read(self.FIFO_LVL)
    def rule_hits(self, i):  return self.ip.read(self.RULE_HIT_BASE + i * 4)
    def anomaly_hits(self, j): return self.ip.read(self.ANOMALY_HIT_BASE + j * 4)

    def status(self):
        """Decode the STATUS register into a dict."""
        s = self.ip.read(self.STATUS)
        return {"has_events": s & 0x1, "empty": (s >> 1) & 0x1,
                "full": (s >> 2) & 0x1, "overflow": (s >> 3) & 0x1}

    def counters(self):
        """Snapshot of all counters as a dict."""
        return {"packets": self.packet_count(),
                "drops": self.drop_count(),
                "fifo_level": self.fifo_level(),
                "rule_hits": [self.rule_hits(i) for i in range(self.NUM_RULES)],
                "anomaly_hits": [self.anomaly_hits(j) for j in range(3)]}

    # -- rule programming ---------------------------------------------------
    def program_rule(self, idx, *, src_ip=0, dst_ip=0, src_prefix=0, dst_prefix=0,
                     src_port=0, dst_port=0, protocol=0, action=ACT_DROP, enable=1):
        """Program rule `idx`. Port/protocol 0 = wildcard; prefix 0 = any IP."""
        base = self.RULE_BASE + idx * 0x10
        self.ip.write(base + 0x0, src_ip & 0xFFFFFFFF)
        self.ip.write(base + 0x4, dst_ip & 0xFFFFFFFF)
        self.ip.write(base + 0x8, ((src_port & 0xFFFF) << 16) | (dst_port & 0xFFFF))
        word3 = ((src_prefix & 0xFF) << 24) | ((dst_prefix & 0xFF) << 16) \
            | ((protocol & 0xFF) << 8) | ((action & 0x7) << 5) | (enable & 0x1)
        self.ip.write(base + 0xC, word3)

    def clear_rule(self, idx):
        """Disable a rule by clearing its enable bit (word3 -> 0)."""
        self.ip.write(self.RULE_BASE + idx * 0x10 + 0xC, 0)

    @staticmethod
    def ip_to_int(dotted):
        """'10.0.0.1' -> 0x0A000001, for use as src_ip/dst_ip in program_rule."""
        a, b, c, d = (int(x) for x in dotted.split("."))
        return (a << 24) | (b << 16) | (c << 8) | d

    # -- datapath -----------------------------------------------------------
    def send_packet(self, pkt_bytes):
        """Send one frame through the engine; return the bytes that came back."""
        in_buf  = allocate(shape=(len(pkt_bytes),), dtype=np.uint8)
        out_buf = allocate(shape=(len(pkt_bytes),), dtype=np.uint8)
        in_buf[:] = np.frombuffer(pkt_bytes, dtype=np.uint8)
        self.dma.recvchannel.transfer(out_buf)   # arm receive FIRST
        self.dma.sendchannel.transfer(in_buf)    # then send
        self.dma.sendchannel.wait()
        self.dma.recvchannel.wait()
        result = bytes(out_buf)
        in_buf.freebuffer()
        out_buf.freebuffer()
        return result

    # -- event FIFO ---------------------------------------------------------
    def drain_event(self):
        """Pop and decode one event, or return None if the FIFO is empty."""
        if self.fifo_level() == 0:
            return None
        ts    = self.ip.read(0x050)
        w1    = self.ip.read(0x054)
        sip   = self.ip.read(0x058)
        dip   = self.ip.read(0x05C)
        ports = self.ip.read(0x060)              # this read auto-pops the FIFO
        ips = lambda x: ".".join(str((x >> s) & 0xFF) for s in (24, 16, 8, 0))
        return {
            "timestamp":  ts,
            "drop":       w1 & 0x1,
            "anomaly":   (w1 >> 1) & 0x7,
            "rule_id":   (w1 >> 4) & 0xF,
            "event_type": (w1 >> 8) & 0xF,       # 0=rule_hit, 1=anomaly
            "src_ip":     ips(sip), "dst_ip": ips(dip),
            "src_port":  (ports >> 16) & 0xFFFF, "dst_port": ports & 0xFFFF,
        }

    def drain_all_events(self, limit=256):
        """Drain every event currently in the FIFO into a list."""
        events = []
        while self.fifo_level() and len(events) < limit:
            events.append(self.drain_event())
        return events


# ---------------------------------------------------------------------------
# Self-test / demo: run this file directly on the board to validate the build.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    from pynq import Overlay

    ol = Overlay("packet_inspector.bit")
    pi = PacketInspector(ol)

    assert pi.version() == 0xDEADBEEF, "VERSION mismatch -- overlay not loaded?"
    print("VERSION ok: 0x%08X" % pi.version())

    pi.program_rule(0, protocol=6, action=PacketInspector.ACT_DROP)  # drop all TCP
    pi.send_packet(build_frame())                                    # one TCP SYN

    print("counters:", pi.counters())
    print("event   :", pi.drain_event())
    print("self-test passed.")
