// =============================================================================
// packet_inspector_pkg.sv
// =============================================================================
// Shared types and constants for the packet inspection pipeline.
// All three modules (header_parser, rule_checker, event_packer) import
// this package, so struct definitions live in exactly one place.
// =============================================================================

package packet_inspector_pkg;

  // ---------------------------------------------------------------------------
  // Configuration parameters
  // ---------------------------------------------------------------------------
  parameter int NUM_RULES        = 8;
  parameter int EVENT_FIFO_DEPTH = 256;
  parameter int MAX_FRAME_BYTES  = 1518;   // jumbo-free Ethernet max

  // ---------------------------------------------------------------------------
  // EtherType constants (from IEEE 802.3)
  // ---------------------------------------------------------------------------
  parameter logic [15:0] ETHERTYPE_IPV4 = 16'h0800;
  parameter logic [15:0] ETHERTYPE_ARP  = 16'h0806;
  parameter logic [15:0] ETHERTYPE_IPV6 = 16'h86DD;
  parameter logic [15:0] ETHERTYPE_VLAN = 16'h8100;

  // ---------------------------------------------------------------------------
  // IP protocol numbers (from IANA)
  // ---------------------------------------------------------------------------
  parameter logic [7:0] IP_PROTO_ICMP = 8'd1;
  parameter logic [7:0] IP_PROTO_TCP  = 8'd6;
  parameter logic [7:0] IP_PROTO_UDP  = 8'd17;

  // ---------------------------------------------------------------------------
  // packet_meta_t -- emitted by header_parser at end-of-packet,
  //                  consumed by rule_checker and event_packer.
  // ---------------------------------------------------------------------------
  typedef struct packed {
    // Layer 2 (Ethernet)
    logic [47:0]  eth_dst_mac;
    logic [47:0]  eth_src_mac;
    logic [15:0]  eth_type;

    // Layer 3 (IPv4)
    logic [3:0]   ip_version;
    logic [3:0]   ip_ihl;
    logic [15:0]  ip_total_length;
    logic [7:0]   ip_protocol;
    logic [31:0]  ip_src;
    logic [31:0]  ip_dst;

    // Layer 4 (TCP / UDP)
    logic [15:0]  l4_src_port;
    logic [15:0]  l4_dst_port;
    logic [7:0]   tcp_flags;        // valid only when ip_protocol == IP_PROTO_TCP

    // Frame-level
    logic [15:0]  frame_length;     // captured byte count
    logic [15:0]  payload_offset;   // first payload byte (reserved Phase 2)

    // Validity flags
    logic         is_ipv4;
    logic         is_tcp;
    logic         is_udp;
    logic         parser_error;
  } packet_meta_t;

  // ---------------------------------------------------------------------------
  // rule_entry_t -- one row of the AXI-Lite-writable rule table.
  //                 Total width: 128 bits (16 bytes per rule).
  // ---------------------------------------------------------------------------
  typedef struct packed {
    logic [31:0]  src_ip;
    logic [31:0]  dst_ip;
    logic [15:0]  src_port;        // 0 = any
    logic [15:0]  dst_port;        // 0 = any
    logic [7:0]   src_prefix_len;  // CIDR mask length, 0-32
    logic [7:0]   dst_prefix_len;
    logic [7:0]   protocol;        // 0 = any
    logic [2:0]   action;          // 0=accept, 1=drop, 2=flag-only
    logic [3:0]   reserved;
    logic         enable;
  } rule_entry_t;

  // ---------------------------------------------------------------------------
  // verdict_t -- from rule_checker to event_packer.
  // ---------------------------------------------------------------------------
  typedef struct packed {
    logic [7:0]  rule_hit_mask;   // bit N = rule N matched
    logic [2:0]  rule_id;         // lowest-index matching rule
    logic [2:0]  anomaly_bits;    // {ip_len_mismatch, tcp_syn_fin, bad_ihl}
    logic        any_hit;
    logic        drop;
  } verdict_t;

  // ---------------------------------------------------------------------------
  // event_entry_t -- 160 bits / 5 words, one entry per flagged packet.
  // PS reads it by reading 5 consecutive 32-bit AXI-Lite registers.
  // ---------------------------------------------------------------------------
  typedef struct packed {
    logic [31:0]  timestamp;       // word 0
    logic [3:0]   event_type;      // word 1: 0=rule_hit, 1=anomaly, 2=payload_match (Ph2)
    logic [3:0]   rule_id;         //   "
    logic [2:0]   anomaly_bits;    //   "
    logic [7:0]   ip_protocol;     //   "
    logic [7:0]   tcp_flags;       //   "
    logic         drop;            //   "
    logic [3:0]   reserved;        //   " (padding to 32 bits)
    logic [31:0]  src_ip;          // word 2
    logic [31:0]  dst_ip;          // word 3
    logic [15:0]  src_port;        // word 4
    logic [15:0]  dst_port;        //   "
  } event_entry_t;

endpackage : packet_inspector_pkg