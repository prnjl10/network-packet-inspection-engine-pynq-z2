# Interview Prep: Network Packet Inspection on FPGA

This document covers the concepts you should be able to discuss in interviews related to network packet inspection, FPGA acceleration of network workloads, and hardware-software co-design. It's organized as Q&A so you can self-quiz. Each answer has a *core* (the short version you'd give in an interview) and a *depth* (what to expand into if the interviewer asks follow-ups).

---

## Section 1: Network Packet Fundamentals

### Q: What is a network packet?

**Core:** A small, self-contained chunk of bytes (typically 60-1500 bytes) that carries data from one machine to another over a network. It contains a header (metadata about routing, addressing, and content) at the front and a payload (the actual data) after.

**Depth:** Networks don't move data as continuous streams — they break communication into discrete packets because physical links have practical size limits, routing decisions are made per-packet, and errors in one packet don't corrupt the whole transmission. Each packet is independent and self-describing. The destination reassembles them if needed.

---

### Q: Why are network protocols layered?

**Core:** Different addressing needs operate at different scopes. MAC addresses work locally (within one switch or LAN); IP addresses work globally (across the entire internet); port numbers work per-application (within one host). No single addressing scheme handles all three jobs, so they're separated into distinct layers that nest inside each other.

**Depth:** The classic analogy is mailing a postcard from California to Tokyo. The transit label ("send to LA hub") gets rewritten at every postal hop — that's Layer 2 (Ethernet). The destination address ("Tokyo, 123 Main St") stays unchanged the whole journey — that's Layer 3 (IP). The "To: Bob" inside the envelope identifies the recipient at the destination — that's Layer 4 (port number). Each layer's protocol doesn't know or care about the layers above or below it.

---

### Q: What does a typical TCP/IP packet look like on the wire?

**Core:** A sequence of bytes structured as four sections in this order: Ethernet header (14 bytes), IP header (20 bytes), TCP or UDP header (20 or 8 bytes), and then the payload.

**Depth:**

```
Bytes 0-13:    Ethernet header
Bytes 14-33:   IP header
Bytes 34-53:   TCP header (or 34-41 if UDP)
Bytes 54+:     Payload
```

Each section has fixed-position fields, like a form. The headers are read in order — Ethernet first, then IP, then L4 — because each one's "what comes next" field tells the parser how to interpret the bytes after it.

---

## Section 2: Ethernet (Layer 2)

### Q: What's in an Ethernet frame?

**Core:** Three fields totaling 14 bytes: a 6-byte destination MAC address, a 6-byte source MAC address, and a 2-byte EtherType. Then comes the payload.

**Depth:** Layout:
```
Bytes 0-5:   Destination MAC (which NIC should accept this)
Bytes 6-11:  Source MAC (which NIC sent it)
Bytes 12-13: EtherType (what's inside — 0x0800 for IPv4)
```

There's also a 4-byte FCS (frame check sequence / CRC) at the end of the frame, but the MAC controller usually strips and validates it before the bytes reach your processing logic, so you can ignore it.

---

### Q: What is a MAC address?

**Core:** A 6-byte (48-bit) hardware address identifying a NIC on a local network segment. Written as 12 hex digits with colons (`AA:BB:CC:DD:EE:FF`). Globally unique, baked into the NIC at manufacture (though it can be spoofed).

**Depth:** MAC addresses only mean something within a single broadcast domain — one Ethernet cable, one switch, one Wi-Fi network. When a packet crosses a router (which separates broadcast domains), the Ethernet header is stripped and rebuilt with new MAC addresses for the next segment. This is why MAC addresses are hop-by-hop, not end-to-end.

Special MACs: `FF:FF:FF:FF:FF:FF` is broadcast (every NIC accepts); MACs starting with `01:` are multicast.

---

### Q: What is the EtherType field for?

**Core:** A 2-byte field that tells the receiver what kind of packet is inside the Ethernet payload. Common values: `0x0800` = IPv4, `0x0806` = ARP, `0x86DD` = IPv6, `0x8100` = VLAN tag.

**Depth:** In a packet parser, EtherType is the trigger for the next FSM state. If it's `0x0800`, transition to "parse IPv4 header." Otherwise, the parser typically passes the packet through without interpreting L3/L4 fields. This is the first "type dispatch" in the parsing pipeline.

---

### Q: When a packet leaves your laptop heading to Google, what does the Ethernet destination address contain?

**Core:** Your router's MAC address, not Google's.

**Depth:** Your laptop has no way to know Google's MAC, and even if it did, it couldn't use it because MAC addresses are only meaningful within the local network segment. To reach anywhere outside your subnet, your laptop sends the packet to its default gateway (the router). The router's MAC is resolved from the router's IP via ARP (Address Resolution Protocol). At the router, the Ethernet header gets stripped and rebuilt with new MACs for the next hop. This happens at every router along the path. The IP header, by contrast, stays untouched the whole way.

---

## Section 3: IP / Layer 3

### Q: What's in the IPv4 header?

**Core:** 20 bytes (no options) containing version, header length, total length, identification, flags, TTL, protocol, checksum, source IP, and destination IP.

**Depth:** Layout (positions relative to start of IP header):
```
Byte  0:     Version (4 bits) + IHL (4 bits)
Byte  1:     Type of Service
Bytes 2-3:   Total Length
Bytes 4-5:   Identification
Bytes 6-7:   Flags + Fragment Offset
Byte  8:     TTL
Byte  9:     Protocol
Bytes 10-11: Header Checksum
Bytes 12-15: Source IP
Bytes 16-19: Destination IP
```

For Phase 1 of your project, only four of these matter: Version+IHL (for `bad_ihl` anomaly), Total Length (for `ip_len_mismatch`), Protocol (to decide TCP vs UDP next), and the two IP addresses (for rule matching).

---

### Q: What is the IHL field and why does it matter?

**Core:** IHL = "Internet Header Length," a 4-bit field giving the IP header size in 32-bit words. For a normal header without options, IHL = 5, meaning 5 × 4 = 20 bytes. A value below 5 is invalid.

**Depth:** This tells the parser where the IP header ends and the L4 header begins. If IHL = 5, the L4 header starts at byte 34 of the packet. If IHL = 6 (rare), the IP header is 24 bytes and L4 starts at byte 38. If IHL < 5, the packet is malformed — your inspector flags this as the `bad_ihl` anomaly.

---

### Q: What is the Protocol field?

**Core:** A 1-byte field in the IP header indicating what comes after IP. Values: 6 = TCP, 17 = UDP, 1 = ICMP.

**Depth:** Same role as EtherType plays for the Ethernet→IP transition, now for the IP→L4 transition. Your parser's FSM uses this to decide whether to invoke the TCP-parsing logic, UDP-parsing logic, or neither.

---

### Q: How is an IP address represented in memory vs. how humans write it?

**Core:** An IPv4 address is 4 bytes (32 bits) in network byte order (big-endian). Humans write it in dotted-decimal (`192.168.1.5`), where each dotted segment is one byte expressed in decimal.

**Depth:** `192.168.1.5` corresponds to the four bytes `0xC0 0xA8 0x01 0x05`. On the wire, these come in that exact order. In SystemVerilog, you'd typically store this as a single `logic [31:0]` value with the most significant byte being the first byte received from the AXI-Stream.

---

### Q: Why are IP addresses different from MAC addresses if both are just numeric IDs?

**Core:** Because they solve different routing problems at different scales. MAC addresses are flat and only locally meaningful — they can't be routed across the global internet. IP addresses are hierarchical (network + host portions) and can be routed end-to-end. Both exist because no single addressing scheme handles both scopes efficiently.

**Depth:** Imagine if every router in the world had to keep a forwarding table indexed by MAC address — that table would have billions of entries with no structure to aggregate them. IP addresses group hosts into networks (via subnetting), so routers can aggregate millions of hosts behind a single route entry. That hierarchical structure is what makes internet-scale routing tractable.

---

## Section 4: TCP and UDP / Layer 4

### Q: What's the difference between TCP and UDP?

**Core:** TCP is connection-oriented and reliable; UDP is connectionless and unreliable. Both add port numbers so multiple applications on the same host can communicate independently.

**Depth:** TCP establishes a connection via a 3-way handshake (SYN, SYN-ACK, ACK), acknowledges every byte received, retransmits lost data, and tears down the connection cleanly. The price is latency and overhead. UDP just sends packets independently with no setup, no acknowledgments, no retransmission. The price is no delivery guarantee.

Web traffic uses TCP because corrupted pages break. DNS lookups use UDP because the query/response is tiny and re-querying is cheaper than maintaining a TCP connection. Voice and video use UDP because retransmitting a lost frame ruins real-time playback.

---

### Q: What is a port number?

**Core:** A 16-bit number (0-65535) identifying a specific application or service on a host. Well-known assignments: 80 = HTTP, 443 = HTTPS, 53 = DNS, 22 = SSH, 25 = SMTP.

**Depth:** Lives in the first 4 bytes of the TCP or UDP header (2 bytes for source port, 2 bytes for destination port). Ports 0-1023 are "well-known" and assigned by IANA. 1024-49151 are "registered" for specific applications. 49152-65535 are dynamic / ephemeral, used by clients picking a temporary port for outgoing connections.

---

### Q: What are TCP flags?

**Core:** A 6-bit field in byte 13 of the TCP header controlling connection state. The six standard flags: SYN (start connection), ACK (acknowledging data), FIN (close connection), RST (forcibly reset), PSH (deliver immediately), URG (urgent data present).

**Depth:** Normal TCP traffic patterns: SYN starts a handshake, SYN+ACK accepts it, ACK completes it, FIN+ACK closes politely. Illegal or suspicious patterns: SYN+FIN in the same packet (meaningless — start and end simultaneously), no flags at all (NULL scan, used for stealth port scanning), all flags set (Xmas scan).

For your project, the `tcp_syn_fin` anomaly is detected by checking whether the SYN bit AND the FIN bit are both set in byte 13.

---

### Q: What is the TCP 3-way handshake?

**Core:** The three packets exchanged to establish a TCP connection. Client sends SYN, server replies SYN+ACK, client replies ACK. After that, data can flow.

**Depth:** The handshake also synchronizes sequence numbers so each side knows where the other's data stream starts. Sequence numbers are randomized to defend against blind injection attacks. The whole handshake costs one round-trip time (RTT) before any actual data is sent, which is why latency-sensitive protocols sometimes prefer UDP.

---

### Q: How would you detect a port scan in hardware?

**Core:** A port scan typically sends SYN packets to many destination ports on one host, waiting for SYN-ACK (port open) or RST (port closed) responses. You'd detect it by tracking SYN-only packets per source IP, counting unique destination ports per source over a time window, and flagging when the count exceeds a threshold.

**Depth:** This requires per-flow state in hardware, which is more complex than the stateless anomaly checks in Phase 1. You'd use a hash table or CAM keyed on source IP, with each entry tracking the set of destination ports seen recently. The hash table grows large quickly under attack, so production designs use Bloom filters or count-min sketches as approximations. Out of scope for Phase 1, but a natural Phase 3 extension.

---

## Section 5: Packet Inspection Concepts

### Q: What is packet inspection?

**Core:** Reading the headers (and sometimes the payload) of network packets to make decisions: forward, drop, log, alert, classify, or shape.

**Depth:** Packet inspection sits at the intersection of networking, security, and performance. It's done by firewalls, intrusion detection systems, load balancers, traffic shapers, network monitors, and DPI engines. The depth of inspection ranges from "look at the IP destination" (a basic router does this) to "parse application-layer fields and search for malware signatures in payload" (a deep packet inspector).

---

### Q: What's the difference between header inspection and DPI?

**Core:** Header inspection examines only the protocol headers (Ethernet, IP, TCP/UDP). Deep packet inspection (DPI) examines the payload too — what's actually being communicated above the transport layer.

**Depth:** Header inspection is enough to enforce policies based on IPs, ports, and protocols ("block traffic to 10.0.0.0/8 from outside our network"). DPI is needed when the policy depends on payload content ("block traffic containing this malware signature" or "rate-limit traffic that looks like BitTorrent"). DPI is computationally expensive — modern firewalls do most of their work at the header level and only invoke DPI when a policy requires it.

---

### Q: Firewall vs IDS vs IPS — what's the difference?

**Core:** A firewall (or IPS) actively blocks bad traffic. An IDS detects and reports bad traffic but doesn't block it. The matching/decision logic is similar; the difference is whether the system sits inline (can drop packets) or out-of-band (can only observe).

**Depth:** An IPS (Intrusion Prevention System) is essentially an IDS with enforcement enabled — same detection logic, plus drop authority. The placement matters: an out-of-band IDS taps off a SPAN port on a switch and observes a copy of traffic; an inline IPS or firewall sits in the data path and can stop packets. For your PYNQ-Z2 project, the PL pipeline is out-of-band (PS already received the packet via GEM), so it's an IDS in this configuration.

---

### Q: What's the difference between stateless and stateful inspection?

**Core:** Stateless inspection looks at each packet independently — it doesn't remember anything about prior packets. Stateful inspection tracks per-flow state (the set of active TCP connections, for example) so it can enforce policies that depend on connection history.

**Depth:** Phase 1 of your project is purely stateless — every rule and every anomaly check depends only on fields in the current packet. Stateful inspection would let you enforce things like "drop any TCP packet that doesn't belong to an established connection," which requires a connection table indexed by 5-tuple. Stateful is more powerful but much more expensive in hardware — every match requires a lookup, and the connection table needs to age out entries.

---

### Q: What kinds of attacks can header inspection detect?

**Core:** Malformed packets (bad IHL, illegal flag combinations, length mismatches), known-bad source or destination addresses (IP blocklists), known-suspicious port activity (SSH on a port other than 22, traffic to known C&C ports), and protocol-level scans (SYN floods, NULL scans, Xmas scans).

**Depth:** Header inspection can't detect attacks where the *content* is malicious but the headers are normal — SQL injection in an HTTP request, XSS in a web form, malware downloads. Those require DPI. Header inspection also misses anything carried inside encrypted traffic (TLS/HTTPS), because the payload after the TLS handshake is opaque.

---

## Section 6: FPGA Advantages for Packet Inspection

### Q: Why use an FPGA for packet inspection instead of a CPU?

**Core:** Five reasons: line-rate throughput without saturation, deterministic latency, massive parallelism, CPU offload, and graceful performance under attack.

**Depth:** Software inspection is fundamentally bottlenecked by CPU cycles, memory bandwidth, and interrupt overhead. Even highly optimized stacks like DPDK or eBPF/XDP saturate at moderate line rates under realistic rule-set sizes. FPGAs run the inspection logic as a custom data-flow pipeline that processes packets as they arrive on the wire — no kernel-userspace copies, no cache misses on data structures, no syscall overhead, no GC pauses.

---

### Q: Why is the FPGA's parallelism a structural advantage over a CPU?

**Core:** A CPU has a small number of cores running instructions sequentially. An FPGA can match every rule in the rule table in parallel within a single clock cycle, run multiple anomaly checks simultaneously, and pipeline different packets at different pipeline stages. For 8 rules, software does 8 sequential comparisons; hardware does 8 simultaneous comparisons.

**Depth:** This scales: 64 rules in software is 8× slower than 8 rules; 64 rules in hardware is roughly the same speed as 8 rules (until you hit physical resource limits). The FPGA also enables specialized data paths — for example, a TCAM (Ternary Content-Addressable Memory) structure that does longest-prefix-match in O(1), versus software's O(log N) trie traversal.

---

### Q: What does "deterministic latency" mean and why does it matter?

**Core:** A hardware pipeline takes the same number of clock cycles to process every packet, regardless of system load. The latency is predictable to the nanosecond. Software latency varies based on cache state, context switches, interrupt timing, scheduler behavior, and many other factors.

**Depth:** Determinism matters for time-sensitive applications (financial trading, industrial control, real-time monitoring). In a software inspection pipeline, a packet might take 5 µs on average but occasionally 50 µs when a cache miss hits or a context switch occurs. In an FPGA, the latency is a fixed constant — say 200 ns — for every packet, with no jitter. This also makes it much easier to characterize and verify the system's behavior under worst case.

---

### Q: Why does FPGA inspection scale gracefully under DoS attack?

**Core:** A software inspector running at 1 Gbps under normal load might be 30% CPU. Under a 10× traffic spike, it tries to consume 300% CPU — which is impossible, so it drops packets and falls behind. An FPGA pipeline runs at line rate by design — if it can do 1 Gbps, it does 1 Gbps regardless of whether the rule set is empty or full. There's no "running out of CPU" failure mode.

**Depth:** This is a security property, not just a performance one. Software inspectors can be DoSed by the very traffic they're inspecting — flood them with crafted packets that trigger expensive rules, and they collapse. Hardware inspectors don't have this attack surface in the data path. (The control path — rule updates from software — might still be vulnerable, but that's a separate concern.)

---

### Q: What does "inline" mean for packet processing and why is it special on FPGA?

**Core:** Inline means the packet flows through the processing logic on its way to its destination, not as a copy on a side channel. An FPGA can put inspection logic directly in the data path of a NIC, so every packet gets inspected with zero added latency relative to "not being inspected."

**Depth:** This is how smart-NICs (NVIDIA BlueField, AMD Pensando) work. The FPGA or custom ASIC sits between the PHY and the host's PCIe bus. Packets flow through the inspection pipeline as part of their normal path; there's no separate "send to inspector, get verdict, then forward" round-trip. Out-of-band inspection (SPAN port to a separate device) always has higher latency and can never enforce — only detect.

---

### Q: When should you NOT use an FPGA for packet inspection?

**Core:** When your traffic volume doesn't justify it, when your rules are highly dynamic (changing every few seconds), when you need very deep payload analysis with complex regex (which is hard in hardware), or when development cost / time-to-deploy outweighs the runtime benefits.

**Depth:** FPGAs have higher up-front cost — both hardware and engineering hours. For traffic under a few hundred Mbps with stable rules, software inspection (Snort/Suricata) is often the right choice. FPGAs shine at 1 Gbps and up, where software is fundamentally not viable. The cost-benefit also depends on the cost of dropped packets: a financial exchange or industrial control system pays whatever it costs to avoid them; a small office network does not.

---

## Section 7: Project-Specific Concepts

### Q: What does your project architecture look like?

**Core:** Three custom RTL modules — `header_parser`, `rule_checker`, `event_packer` — connected as a pipeline. Wrapped by standard Xilinx IP (AXI-DMA, AXI-Stream FIFO, AXI Interconnect) from the Vivado block design. The PS (ARM Cortex-A9 running Linux) loads the overlay, configures rules over AXI-Lite, feeds packets in via AXI-DMA, and polls events out over AXI-Lite. A Jupyter notebook visualizes counters and events live.

**Depth:** The parser extracts L2/L3/L4 header fields into a structured metadata bus. The rule checker compares metadata against eight software-programmable 5-tuple rules and three hard-coded anomaly checks in parallel, producing a verdict. The event packer maintains counters, captures hits into a FIFO, and exposes everything via an AXI-Lite slave port.

---

### Q: What is AXI-Stream and why is it used here?

**Core:** AXI-Stream is the ARM AMBA standard for streaming data interfaces. It uses a simple valid/ready handshake (`TVALID`/`TREADY`) per beat of data, plus optional sideband signals (`TKEEP`, `TLAST`, `TUSER`). It's the natural fit for packet data because packets are streams of bytes that arrive one beat at a time.

**Depth:** Key signals: `TDATA` carries the actual bytes; `TVALID` asserts when the source has data; `TREADY` asserts when the sink can accept; `TLAST` asserts on the last beat of a packet; `TKEEP` indicates which bytes of `TDATA` are valid (relevant when packet length isn't a multiple of the bus width); `TUSER` is a user-defined sideband that's commonly used for per-packet metadata or per-beat flags.

---

### Q: What are the three hard-coded anomaly checks in your project?

**Core:** `bad_ihl`, `tcp_syn_fin`, and `ip_len_mismatch`.

**Depth:**
- `bad_ihl`: IPv4 IHL field is less than 5. A header cannot be shorter than 20 bytes by definition.
- `tcp_syn_fin`: A TCP packet has both the SYN and FIN flag bits set. These are mutually exclusive — you can't initiate and tear down a connection in the same packet.
- `ip_len_mismatch`: The IP header's Total Length field disagrees with the actual byte count of the received frame (frame length minus 14 bytes of Ethernet header). Indicates a truncated or malformed packet.

---

### Q: How would you verify the header parser?

**Core:** Per-module directed testbenches in SystemVerilog that inject crafted Ethernet frames covering normal cases (IPv4/TCP, IPv4/UDP, ICMP), edge cases (minimum-size frames, frames with non-IPv4 EtherTypes), and adversarial cases (malformed headers, truncated packets). Compare the parser's metadata output against a reference table.

**Depth:** Beyond directed tests, more rigorous verification would include: constrained-random stimulus to generate millions of synthetically varied frames; functional coverage on every header field and every state transition; SystemVerilog assertions on the AXI-Stream handshake protocol; and formal property verification using a tool like Symbiyosys to prove the parser FSM never deadlocks. The richer methodology is publication-grade and is the natural Phase 2 of the verification effort.

---

### Q: What's the role of the FIFO in the event packer?

**Core:** A 256-entry buffer holding flagged-packet events between hardware generation and software consumption. It decouples the rate at which hits occur (potentially line rate) from the rate at which the PS can drain events (orders of magnitude slower).

**Depth:** Without a FIFO, the hardware would have to either back-pressure the pipeline whenever the PS was slow (catastrophic at line rate), or drop events silently (loses information). The FIFO absorbs bursts, and overflow is reported as a sticky status bit so the PS knows when events were lost. FIFO sizing is a classic verification target — you want to demonstrate that the FIFO is large enough for realistic burst patterns but not so large it wastes BRAM.

---

### Q: Why split the inspector into parser, rule checker, and event packer instead of one big module?

**Core:** Three reasons: clean verification boundaries (each module has a well-defined interface and can be tested in isolation), reusability (the parser could feed a different policy engine in a future project), and architectural extensibility (Phase 2's payload pattern matcher drops in as a sibling of the rule checker without touching either neighbor).

**Depth:** This is the same modularity principle that drives microservices in software or block-level IP in chip design. Each module has one job and one interface to the next. When something breaks, you can isolate which module is at fault. When requirements change, you can replace one module without rewriting the others. It's also the right shape for a portfolio piece — clean module boundaries demonstrate engineering discipline.

---

## Quick Reference Cheat Sheet

**Layer 2 — Ethernet (14 bytes)**
- 0-5: Dest MAC, 6-11: Src MAC, 12-13: EtherType
- 0x0800 = IPv4, 0x0806 = ARP, 0x86DD = IPv6

**Layer 3 — IPv4 (20 bytes)**
- 0: Version+IHL (normal = 0x45)
- 2-3: Total Length
- 8: TTL, 9: Protocol
- 12-15: Src IP, 16-19: Dst IP
- Protocol values: 6 = TCP, 17 = UDP, 1 = ICMP

**Layer 4 — TCP (20 bytes minimum)**
- 0-1: Src port, 2-3: Dst port
- 4-7: Seq num, 8-11: Ack num
- 13: Flags byte (FIN=bit0, SYN=bit1, RST=bit2, PSH=bit3, ACK=bit4, URG=bit5)

**Layer 4 — UDP (8 bytes)**
- 0-1: Src port, 2-3: Dst port, 4-5: Length, 6-7: Checksum

**Well-known ports**
- 22 = SSH, 25 = SMTP, 53 = DNS, 80 = HTTP, 443 = HTTPS

**FPGA advantages (one-liners)**
- Line-rate throughput without CPU saturation
- Deterministic latency, no OS jitter
- Massive parallelism — all rules matched in one cycle
- CPU offload — host free for other work
- Graceful under DoS — software collapses, hardware doesn't

**Three anomalies in Phase 1**
- `bad_ihl`: IPv4 IHL < 5
- `tcp_syn_fin`: SYN and FIN flag bits both set
- `ip_len_mismatch`: IP Total Length disagrees with frame length

**Firewall vs IDS vs IPS**
- Firewall = IPS = active blocker (inline)
- IDS = passive observer (out-of-band)
- Phase 1 is technically an IDS

---

## Suggested Practice

Before any interview where this material might come up:

1. Be able to draw the byte layout of an Ethernet/IPv4/TCP packet from memory.
2. Be able to explain hop-by-hop vs. end-to-end addressing in 60 seconds without notes.
3. Be able to give the FPGA advantages in 30 seconds, with at least one concrete example for each.
4. Be able to walk through your project's pipeline (parser → rule_checker → event_packer) and justify why each module exists.
5. Be able to describe at least one verification strategy for the header parser.

If you can do all five fluently, you're in good shape for a DV-engineer-targeting-networking-hardware interview.
