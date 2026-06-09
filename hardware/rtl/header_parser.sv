/*
Header Parser (Block 1 of the Packet Inspection Pipeline)

PURPOSE: The packet inspector's header parser consumes an 8-bit AXI-Stream
packet, walks the L2/L3/L4 headers byte by byte, and extracts the fields the
downstream rule_checker needs into a structured packet_meta_t bundle. The
full packet is also passed through unchanged on a second AXI-Stream so the
event_packer can attach the verdict bits in TUSER without buffering the
packet itself.

INPUTS:
- aclk: clock (125 MHz target, drives the entire pipeline)
- aresetn: synchronous active-low reset
- s_axis_tdata [7:0]: one byte per beat from the upstream width converter
  (64-bit DMA stream is adapted down to 8 bits before reaching this block)
- s_axis_tvalid: indicates s_axis_tdata is meaningful this cycle
- s_axis_tlast: end-of-packet marker, asserts on the final byte of a packet
- m_axis_tready: downstream readiness (declared but unused in v1)

OUTPUTS:
- s_axis_tready: always 1'b1 in v1 (no backpressure). Parser unconditionally
  accepts data; the downstream FIFO absorbs any throughput mismatch.
- m_axis_tdata, m_axis_tvalid, m_axis_tlast: combinational passthrough of
  the input AXI-Stream so event_packer sees the same packet.
- m_axis_tuser_payload_valid: sideband signal HIGH on payload bytes only
  (state == READ_PAYLOAD). Reserved for Phase 2's pattern matcher.
- meta [packet_meta_t]: structured bundle of all captured + derived header
  fields, intended for the rule_checker.
- meta_valid: one-cycle pulse asserted the cycle AFTER TLAST, signaling
  that the meta bundle is stable and ready to be sampled.

INTERNAL STATE:
- FSM has 5 states:
    * IDLE          - no packet in flight; waiting for first valid byte
    * READ_ETH      - walking the 14-byte Ethernet header (bytes 0-13)
    * READ_IP       - walking the 20-byte IPv4 header (bytes 14-33),
                      entered only when eth_type == 0x0800
    * READ_L4       - walking the TCP (20 bytes) or UDP (8 bytes) header
    * READ_PAYLOAD  - streaming payload bytes until TLAST
- Standard two-process FSM: `state` (registered) and `next_state`
  (combinational). Synchronous reset to IDLE.
- byte_count [10:0]: current byte position within the packet (0..1518).
  Increments on every accepted beat, resets to 0 on TLAST.
- frame_length [15:0]: total byte count, latched at TLAST.
- One shift register per captured field (eth_dst_mac, eth_src_mac, eth_type,
  ip_version, ip_ihl, ip_total_length, ip_protocol, ip_src, ip_dst,
  l4_src_port, l4_dst_port, tcp_flags).

HOW IT WORKS:
On every accepted byte (s_axis_tvalid && s_axis_tready), byte_count
increments. A case statement on byte_count selects which field's shift
register to update for the current byte position. Multi-byte fields use
the pattern `field <= {field[N-9:0], s_axis_tdata}`, which produces network
byte order (big-endian) automatically across multiple cycles.

The FSM transitions when byte_count reaches the end of each header layer.
At byte 13 (end of Ethernet), the captured eth_type decides whether to
enter READ_IP or skip ahead to READ_PAYLOAD. At byte 33 (end of IPv4),
ip_protocol decides whether to enter READ_L4 (for TCP/UDP) or skip to
READ_PAYLOAD. At byte 53 (TCP) or 41 (UDP), the L4 header is done and the
FSM enters READ_PAYLOAD. TLAST in any non-IDLE state falls back to IDLE,
handling truncated packets gracefully.

When TLAST arrives, byte_count resets to 0 (ready for the next packet) and
frame_length latches. One cycle later, meta_valid pulses for a single
cycle. The one-cycle delay lets the last byte's shift-register update
settle before downstream samples the meta bundle.

DATA FLOW:
Bytes enter on s_axis_tdata. Each byte triggers a shift-register update for
the matching field (gated on byte_count, not state). The same stream is
passed through to m_axis_* with zero buffering. At end-of-packet, the
captured registers plus combinationally-derived flags (is_ipv4, is_tcp,
is_udp, parser_error, payload_offset) are assembled into the meta struct
via continuous assigns. The meta_valid strobe announces that meta is ready
for the rule_checker.

KEY DESIGN DECISIONS:
1. **8-bit byte-oriented internal datapath.** A Xilinx axis_dwidth_converter
   adapts the 64-bit DMA stream down to 8 bits before this block. Walking
   one byte per cycle makes field extraction trivial: each field
   accumulates in a shift register at a specific byte_count. At 125 MHz,
   this hits exactly 1 Gbps line rate -- matches the PYNQ-Z2 Ethernet PHY.

2. **byte_count-driven captures, not FSM-driven.** Shift register updates
   are gated on byte_count alone, independent of FSM state. This decouples
   field positions from layer transitions and avoids subtle bugs where
   state lags the byte index by a cycle. Byte N is always associated with
   the same field, period.

3. **FSM as layer marker, not capture gate.** State drives only two things:
   the next-state decision (which captured field to look at) and the
   tuser_payload_valid sideband. Captures themselves don't reference state.

4. **Shift register produces network byte order automatically.** Pattern
   `{field[N-9:0], new_byte}` builds big-endian values across N/8 cycles
   without any byte-swapping logic. Matches Ethernet/IPv4/TCP wire format.

5. **Derived flags via assign, not registers.** is_ipv4, is_tcp, is_udp,
   parser_error, and payload_offset are combinational from the captured
   fields. Costs nothing extra in flops and stays coherent with the
   captured values by construction.

6. **Registered meta_valid (one cycle after TLAST).** Delayed by one cycle
   so the final-byte shift-register updates settle before the downstream
   rule_checker samples meta. Without this, the values for the last byte
   would be stale.

7. **No backpressure in v1.** s_axis_tready is hardcoded to 1'b1. A
   downstream AXI-Stream FIFO absorbs any short-term throughput mismatch.
   When the project moves to higher rule counts that may not meet timing,
   real backpressure can be wired through with no module restructuring.

EDGE CASES:
- **Non-IPv4 packets (ARP, IPv6, VLAN-tagged, etc.).** At byte 13 the FSM
  notices eth_type != 0x0800 and goes directly to READ_PAYLOAD, skipping
  the IPv4 and L4 captures. is_ipv4 emerges as 0; rule_checker simply
  won't match any IPv4-based rules. No error, no stall.

- **Non-TCP/UDP IPv4 packets (ICMP, etc.).** At byte 33 the FSM notices
  ip_protocol is neither TCP nor UDP and skips READ_L4. l4_*_port and
  tcp_flags retain whatever values were left from the previous packet
  (they'll be overwritten next time those positions hit anyway).

- **Truncated or malformed packets.** Every non-IDLE state has an
  if (s_axis_tlast) -> IDLE fallback. If TLAST arrives before the FSM
  expected the packet to end, it returns to IDLE cleanly instead of
  stalling. parser_error is asserted in the meta bundle when
  frame_length < 14 (didn't even complete the Ethernet header).

- **Idle cycles between packets.** When s_axis_tvalid is low, byte_count,
  all field registers, and FSM state freeze. The pipeline resumes cleanly
  when traffic returns.

- **Reset behavior.** On aresetn LOW, state forces to IDLE, byte_count
  and frame_length clear to 0, and all 12 captured field registers
  clear to 0. meta_valid forces low. No spurious outputs during reset.

- **Latency.** From TLAST at the parser input to meta_valid asserting, the
  delay is exactly 2 cycles (1 for the final-byte shift to land, 1 for
  the meta_valid register). Throughput is limited only by the input byte
  rate, not by pipeline depth.
*/

import packet_inspector_pkg::*;

module header_parser (
  input  logic           aclk,
  input  logic           aresetn,

  // Input stream from upstream width converter (one byte per beat)
  input  logic [7:0]     s_axis_tdata,
  input  logic           s_axis_tvalid,
  output logic           s_axis_tready,
  input  logic           s_axis_tlast,

  // Output stream forwarded to event_packer (full packet passthrough)
  output logic [7:0]     m_axis_tdata,
  output logic           m_axis_tvalid,
  input  logic           m_axis_tready,
  output logic           m_axis_tlast,
  output logic           m_axis_tuser_payload_valid,

  // Parsed metadata to rule_checker (valid for one cycle per packet)
  output packet_meta_t   meta,
  output logic           meta_valid
);

  // v1: no backpressure. Parser always accepts data when it arrives.
  // If the downstream ever needs to throttle, gate this with m_axis_tready.
  assign s_axis_tready = 1'b1;


  // ---------------------------------------------------------------------------
  // FSM state declaration
  //
  // State tracks which protocol layer is being walked. Field captures are
  // actually gated on byte_count (not on state), so state's main roles are:
  // (a) deciding the next state based on captured fields, and (b) driving
  // the payload_valid sideband output.
  // ---------------------------------------------------------------------------
  typedef enum logic [2:0] {
    IDLE,           // No packet in flight. Waiting for first byte.
    READ_ETH,       // Reading 14-byte Ethernet header.
    READ_IP,        // Reading 20-byte IPv4 header (entered only if EtherType == IPv4).
    READ_L4,        // Reading TCP (20 bytes) or UDP (8 bytes) header.
    READ_PAYLOAD    // Streaming payload bytes until TLAST.
  } state_t;

  state_t state, next_state;


  // ---------------------------------------------------------------------------
  // Internal counters and field-capture registers
  // ---------------------------------------------------------------------------
  logic [10:0] byte_count;        // Position within current packet (0..1518).
  logic [15:0] frame_length;      // Total byte count, latched at TLAST.

  // Layer 2 (Ethernet)
  logic [47:0] eth_dst_mac;
  logic [47:0] eth_src_mac;
  logic [15:0] eth_type;

  // Layer 3 (IPv4)
  logic [3:0]  ip_version;
  logic [3:0]  ip_ihl;
  logic [15:0] ip_total_length;
  logic [7:0]  ip_protocol;
  logic [31:0] ip_src;
  logic [31:0] ip_dst;

  // Layer 4 (TCP / UDP)
  logic [15:0] l4_src_port;
  logic [15:0] l4_dst_port;
  logic [7:0]  tcp_flags;         // Only meaningful when ip_protocol == TCP.


  // ---------------------------------------------------------------------------
  // FSM state register
  //
  // Two-process FSM: this block holds the current state across clock edges.
  // The combinational next_state logic below decides what value it loads.
  // Synchronous reset to IDLE.
  // ---------------------------------------------------------------------------
  always_ff @(posedge aclk) begin
    if (!aresetn)
      state <= IDLE;
    else
      state <= next_state;
  end


  // ---------------------------------------------------------------------------
  // FSM next-state logic
  //
  // Transitions fire when byte_count reaches the last byte of the current
  // layer. The decision then turns on the captured field that identifies
  // the next layer (eth_type for L2->L3, ip_protocol for L3->L4).
  //
  // Every non-IDLE state falls back to IDLE on TLAST, handling truncated
  // packets cleanly without leaving the FSM stuck.
  // ---------------------------------------------------------------------------
  always_comb begin
    next_state = state;       // default: hold

    case (state)
      IDLE: begin
        if (s_axis_tvalid)
          next_state = READ_ETH;
      end

      READ_ETH: begin
        if (s_axis_tlast)
          next_state = IDLE;
        else if (byte_count == 13 && eth_type == ETHERTYPE_IPV4)
          next_state = READ_IP;
        else if (byte_count == 13 && eth_type != ETHERTYPE_IPV4)
          next_state = READ_PAYLOAD;
      end

      READ_IP: begin
        if (s_axis_tlast)
          next_state = IDLE;
        else if (byte_count == 33 && (ip_protocol == IP_PROTO_TCP || ip_protocol == IP_PROTO_UDP))
          next_state = READ_L4;
        else if (byte_count == 33)
          next_state = READ_PAYLOAD;
      end

      READ_L4: begin
        if (s_axis_tlast)
          next_state = IDLE;
        else if (ip_protocol == IP_PROTO_TCP && byte_count == 53)
          next_state = READ_PAYLOAD;
        else if (ip_protocol == IP_PROTO_UDP && byte_count == 41)
          next_state = READ_PAYLOAD;
      end

      READ_PAYLOAD: begin
        if (s_axis_tlast)
          next_state = IDLE;
      end
    endcase
  end


  // ---------------------------------------------------------------------------
  // byte_count and frame_length
  //
  // byte_count: increments by 1 on every accepted valid beat; resets to 0
  //   on TLAST (so the next packet starts at byte 0) or on system reset.
  //
  // frame_length: latches byte_count + 1 at TLAST. The +1 accounts for
  //   byte_count being 0-indexed; if TLAST hits at byte_count = 13, that
  //   means 14 bytes were received.
  // ---------------------------------------------------------------------------
  always_ff @(posedge aclk) begin
    if (!aresetn) begin
      byte_count   <= 0;
      frame_length <= 0;
    end else begin
      if (s_axis_tlast)
        byte_count <= 0;
      else if (s_axis_tvalid && s_axis_tready)
        byte_count <= byte_count + 1;

      if (s_axis_tvalid && s_axis_tready && s_axis_tlast)
        frame_length <= byte_count + 1;
    end
  end


  // ---------------------------------------------------------------------------
  // Field capture
  //
  // Each multi-byte field uses a shift-register pattern:
  //     field <= {field[N-9:0], s_axis_tdata}
  // This drops the top 8 bits, slides existing bits up by 8, and inserts
  // the new byte at the LSB. After N/8 cycles the field holds the value
  // in network byte order (big-endian) automatically.
  //
  // Bytes that are not captured here are protocol fields not present in
  // packet_meta_t and therefore not needed downstream:
  //   - Byte 15:      IPv4 ToS (not used by inspection rules)
  //   - Bytes 18-22:  IPv4 ID, Flags+FragOffset, TTL (not used)
  //   - Bytes 24-25:  IPv4 Header Checksum (deferred to a later phase)
  //   - Bytes 38-46:  TCP sequence/ack/offset (only flags at 47 matter)
  // Adding any of these later is a single new case branch using the
  // same shift pattern.
  // ---------------------------------------------------------------------------
  always_ff @(posedge aclk) begin
    if (!aresetn) begin
      eth_dst_mac     <= 48'd0;
      eth_src_mac     <= 48'd0;
      eth_type        <= 16'd0;
      ip_version      <= 4'd0;
      ip_ihl          <= 4'd0;
      ip_total_length <= 16'd0;
      ip_protocol     <= 8'd0;
      ip_src          <= 32'd0;
      ip_dst          <= 32'd0;
      l4_src_port     <= 16'd0;
      l4_dst_port     <= 16'd0;
      tcp_flags       <= 8'd0;
    end else if (s_axis_tvalid && s_axis_tready) begin
      case (byte_count)
        // Ethernet header (bytes 0-13)
        0,1,2,3,4,5:
          eth_dst_mac <= {eth_dst_mac[39:0], s_axis_tdata};
        6,7,8,9,10,11:
          eth_src_mac <= {eth_src_mac[39:0], s_axis_tdata};
        12,13:
          eth_type <= {eth_type[7:0], s_axis_tdata};

        // IPv4 header (bytes 14-33, assuming IHL=5)
        14: begin
          ip_version <= s_axis_tdata[7:4];   // high nibble
          ip_ihl     <= s_axis_tdata[3:0];   // low nibble
        end
        16,17:
          ip_total_length <= {ip_total_length[7:0], s_axis_tdata};
        23:
          ip_protocol <= s_axis_tdata;
        26,27,28,29:
          ip_src <= {ip_src[23:0], s_axis_tdata};
        30,31,32,33:
          ip_dst <= {ip_dst[23:0], s_axis_tdata};

        // L4 header (bytes 34+). src/dst port positions are identical for
        // TCP and UDP; tcp_flags is only meaningful when protocol == TCP.
        34,35:
          l4_src_port <= {l4_src_port[7:0], s_axis_tdata};
        36,37:
          l4_dst_port <= {l4_dst_port[7:0], s_axis_tdata};
        47:
          if (ip_protocol == IP_PROTO_TCP)
            tcp_flags <= s_axis_tdata;
      endcase
    end
  end


  // ---------------------------------------------------------------------------
  // meta_valid pulse
  //
  // Registered one-cycle strobe that fires the cycle AFTER TLAST. The
  // one-cycle delay lets the last byte's shift-register update settle
  // before downstream samples the meta bundle.
  // ---------------------------------------------------------------------------
  always_ff @(posedge aclk) begin
    if (!aresetn)
      meta_valid <= 1'b0;
    else
      meta_valid <= s_axis_tvalid && s_axis_tready && s_axis_tlast;
  end


  // ---------------------------------------------------------------------------
  // meta struct assembly
  //
  // Direct passes of the captured registers, plus derived signals computed
  // combinationally from those registers. Derived flags are intentionally
  // not registered so changes ripple through immediately.
  // ---------------------------------------------------------------------------
  // Direct from captured registers
  assign meta.eth_dst_mac     = eth_dst_mac;
  assign meta.eth_src_mac     = eth_src_mac;
  assign meta.eth_type        = eth_type;
  assign meta.ip_version      = ip_version;
  assign meta.ip_ihl          = ip_ihl;
  assign meta.ip_total_length = ip_total_length;
  assign meta.ip_protocol     = ip_protocol;
  assign meta.ip_src          = ip_src;
  assign meta.ip_dst          = ip_dst;
  assign meta.l4_src_port     = l4_src_port;
  assign meta.l4_dst_port     = l4_dst_port;
  assign meta.tcp_flags       = tcp_flags;
  assign meta.frame_length    = frame_length;

  // Derived protocol classification flags
  assign meta.is_ipv4 = (eth_type == ETHERTYPE_IPV4);
  assign meta.is_tcp  = (eth_type == ETHERTYPE_IPV4) && (ip_protocol == IP_PROTO_TCP);
  assign meta.is_udp  = (eth_type == ETHERTYPE_IPV4) && (ip_protocol == IP_PROTO_UDP);

  // Truncated-frame detector: at least one byte received but fewer than a
  // complete Ethernet header (14 bytes).
  assign meta.parser_error = (frame_length > 0) && (frame_length < 14);

  // Byte offset where payload begins; depends on which headers were parsed
  // (more specific cases first).
  assign meta.payload_offset = meta.is_tcp  ? 16'd54 :
                               meta.is_udp  ? 16'd42 :
                               meta.is_ipv4 ? 16'd34 :
                                              16'd14;


  // ---------------------------------------------------------------------------
  // Passthrough output (m_axis_*)
  //
  // The event_packer needs the original packet bytes so it can forward
  // them with verdict bits attached in TUSER. Pure combinational pass --
  // no buffering, no delay.
  //
  // tuser_payload_valid asserts only on payload bytes (state == READ_PAYLOAD)
  // and is reserved for Phase 2's pattern matcher.
  // ---------------------------------------------------------------------------
  assign m_axis_tdata               = s_axis_tdata;
  assign m_axis_tvalid              = s_axis_tvalid;
  assign m_axis_tlast               = s_axis_tlast;
  assign m_axis_tuser_payload_valid = (state == READ_PAYLOAD) && s_axis_tvalid;

endmodule