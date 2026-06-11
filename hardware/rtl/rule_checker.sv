/*
Rule Checker (Block 2 of the Packet Inspection Pipeline)

PURPOSE: The rule_checker consumes the packet_meta_t bundle published by
header_parser, evaluates the packet against 8 software-programmable rules
in parallel, runs 3 hard-coded anomaly detectors, and emits a verdict
indicating which rules matched, which anomalies fired, and whether the
packet should be dropped. The block has no streaming logic and no FSM --
it is a parallel comparator network with one register at the output.

INPUTS:
- aclk: clock (125 MHz target, drives the entire pipeline)
- aresetn: synchronous active-low reset
- meta [packet_meta_t]: parsed header bundle from header_parser, valid
  combinationally for the cycle in which meta_valid is high
- meta_valid: one-cycle pulse from header_parser indicating meta is stable
- rule_table [NUM_RULES] [rule_entry_t]: 8-entry rule table programmed
  by software via the AXI-Lite slave in event_packer. Each entry contains
  src/dst IP + CIDR prefix length, src/dst port (0 = wildcard), protocol
  (0 = wildcard), action, and enable bit.

OUTPUTS:
- verdict [verdict_t]: hit_mask, rule_id, anomaly_bits, drop flag.
- verdict_valid: one-cycle pulse asserted the cycle AFTER meta_valid,
  signaling that verdict is stable and ready to be sampled by event_packer.

INTERNAL STATE:
- Four combinational intermediates: hit_mask[NUM_RULES-1:0],
  anomaly_bits[2:0], rule_id[2:0], drop_packet.
- Per-rule computed masks: src_mask_w[NUM_RULES] and dst_mask_w[NUM_RULES]
  expand each rule's CIDR prefix length into a 32-bit AND-mask.
- One registered verdict_t struct + verdict_valid bit at the output.
- Helper function prefix_to_mask: combinational pure function converting
  CIDR prefix length (0..32) to a 32-bit network-byte-order mask.

HOW IT WORKS:
On every cycle, all 8 rules are evaluated in parallel against the live meta.
Each rule's hit bit is a 6-input AND: rule enabled, src IP matches under
mask, dst IP matches under mask, src port matches (or wildcard), dst port
matches (or wildcard), protocol matches (or wildcard). The 8 hit bits
together form hit_mask. A priority encoder walks hit_mask from index 0
upward and emits the lowest-index match as rule_id.

In parallel, three combinational anomaly detectors run independently of
the rule table -- bad_ihl, tcp_syn_fin, and ip_len_mismatch. The drop_packet
flag is set if any anomaly bit fires OR if a matched rule's action field
is the "drop" code (action == 3'd1). All four intermediates are then
registered into the verdict struct on the next clock edge, gated by
meta_valid. verdict_valid follows meta_valid with a one-cycle delay.

DATA FLOW:
meta arrives combinationally from header_parser. The rule_table is held
statically -- software writes it through the AXI-Lite interface before
traffic begins and rarely changes it. On the cycle meta_valid is high,
the combinational network settles to a final hit_mask / anomaly_bits /
rule_id / drop_packet. On the next clock edge those values are latched
into verdict and verdict_valid pulses. event_packer samples them, and
they hold steady until the next meta_valid.

KEY DESIGN DECISIONS:
1. **Parallel 8-rule compare, no priority TCAM.** Each rule has its own
   dedicated comparator instance, all evaluating every cycle. For 8 rules
   at this complexity it fits comfortably in fabric without compromising
   timing. Scaling to 32+ rules would warrant a TCAM-style structure;
   that change is bounded to this block and doesn't touch the parser.

2. **CIDR prefix length, not full 32-bit mask, in the rule table.**
   Software programs rules in standard networking notation (a /24 is just
   the integer 24, not 0xFFFFFF00). The prefix_to_mask helper expands it
   at the hardware boundary -- trivial cost in fabric, large gain in
   programmability for the AXI-Lite-facing code.

3. **Wildcard-0 semantics on ports and protocol.** A rule with src_port=0
   matches any source port; same for dst_port and protocol. Lets software
   write port-agnostic or protocol-agnostic rules without a separate
   match-everything flag.

4. **Lowest-index priority on rule_id.** When multiple rules match, the
   lowest index wins. Gives software a deterministic ordering -- put
   more-specific rules at lower indices, fall-through catch-alls at
   higher indices.

5. **Enable bit per rule.** Disabled rules unconditionally miss regardless
   of any field value. This lets software stage rule updates safely
   (clear enable, write the entry, set enable) without ever observing
   half-written rules.

6. **Stateless inspection.** No per-flow state, no connection tracking.
   Each packet is evaluated independently against the current rule_table.
   Stateful tracking (e.g., established-only TCP) is a Phase-3+ extension
   that would add a per-flow table without changing this block's interface.

7. **Registered output, combinational interior.** verdict and verdict_valid
   are registered to give a clean single-cycle handoff to event_packer
   and break the long combinational path (8 comparators + priority encoder
   + drop logic). Adds one cycle of latency; doesn't change throughput.

EDGE CASES:
- **No rule matches.** hit_mask = 0 and rule_id defaults to 0. The
  (|hit_mask) guard in the drop_packet expression prevents accidental
  drops via rule_table[0].action when no rule actually fired.

- **Multiple rules match.** rule_id is the lowest index that matched.
  hit_mask carries the full set of matches for downstream consumers that
  want all hits, not just the priority winner.

- **Non-IPv4 packets.** All three anomaly checks gate on meta.is_ipv4 or
  meta.is_tcp. Non-IPv4 packets cannot trigger spurious anomalies even
  though their IP-positional capture registers contain garbage.

- **prefix_len > 32.** prefix_to_mask saturates at 0xFFFFFFFF (exact match).
  Defensive against malformed software writes that could otherwise produce
  undefined shift behavior in synthesis.

- **prefix_len == 0.** Mask is all zeros, so the IP comparison reduces to
  0 == 0, which is always true. Correct /0 behavior: matches any address.

- **Reset.** verdict and verdict_valid clear to zero. Combinational
  intermediates are recomputed every cycle from current inputs and don't
  need explicit reset handling.
*/

import packet_inspector_pkg::*;

module rule_checker (
  input  logic          aclk,
  input  logic          aresetn,

  // Metadata from header_parser
  input  packet_meta_t  meta,
  input  logic          meta_valid,

  // Rule table from AXI-Lite slave (wired in packet_inspector_top)
  input  rule_entry_t   rule_table [NUM_RULES],

  // Verdict output to event_packer (1 cycle after meta_valid)
  output verdict_t      verdict,
  output logic          verdict_valid
);


  // ---------------------------------------------------------------------------
  // Internal combinational signals
  //
  // These are the four intermediate results computed every cycle and then
  // registered into verdict on the cycle after meta_valid.
  // ---------------------------------------------------------------------------
  logic [NUM_RULES-1:0] hit_mask;
  logic [2:0]           anomaly_bits;
  logic [2:0]           rule_id;
  logic                 drop_packet;


  // ---------------------------------------------------------------------------
  // CIDR prefix length -> 32-bit AND-mask conversion
  //
  // Pure combinational helper. Software programs each rule with a CIDR
  // prefix length (0..32) and this function expands it to the 32-bit
  // mask used in the IP comparison: top `prefix_len` bits set, rest zero.
  //
  //   prefix_len = 0   -> 0x00000000  (matches any IP)
  //   prefix_len = 24  -> 0xFFFFFF00  (matches a /24 subnet)
  //   prefix_len = 32  -> 0xFFFFFFFF  (exact match)
  // ---------------------------------------------------------------------------
  function automatic logic [31:0] prefix_to_mask(input logic [7:0] prefix_len);
    if (prefix_len == 0)
      return 32'h00000000;
    else if (prefix_len >= 32)
      return 32'hFFFFFFFF;
    else
      return 32'hFFFFFFFF << (32 - prefix_len);
  endfunction


  // ---------------------------------------------------------------------------
  // Per-rule 5-tuple match (8 parallel comparisons)
  //
  // For each rule i, hit_mask[i] is 1 if ALL six conditions are true:
  //   - rule_table[i].enable
  //   - src IP matches under the rule's CIDR mask
  //   - dst IP matches under the rule's CIDR mask
  //   - src port matches OR the rule specifies port 0 (wildcard)
  //   - dst port matches OR the rule specifies port 0 (wildcard)
  //   - protocol matches OR the rule specifies protocol 0 (wildcard)
  //
  // The for-loop is unrolled at elaboration -- Vivado generates 8 parallel
  // comparator blocks, all running every cycle. No sequential iteration.
  // ---------------------------------------------------------------------------
  logic [31:0] src_mask_w [NUM_RULES];
  logic [31:0] dst_mask_w [NUM_RULES];

  always_comb begin
    for (int i = 0; i < NUM_RULES; i++) begin
      src_mask_w[i] = prefix_to_mask(rule_table[i].src_prefix_len);
      dst_mask_w[i] = prefix_to_mask(rule_table[i].dst_prefix_len);

      hit_mask[i] = rule_table[i].enable
                 && ((meta.ip_src & src_mask_w[i]) == (rule_table[i].src_ip & src_mask_w[i]))
                 && ((meta.ip_dst & dst_mask_w[i]) == (rule_table[i].dst_ip & dst_mask_w[i]))
                 && ((rule_table[i].src_port == 0) || (meta.l4_src_port == rule_table[i].src_port))
                 && ((rule_table[i].dst_port == 0) || (meta.l4_dst_port == rule_table[i].dst_port))
                 && ((rule_table[i].protocol == 0) || (meta.ip_protocol == rule_table[i].protocol));
    end
  end


  // ---------------------------------------------------------------------------
  // Anomaly detection (3 hard-coded checks)
  //
  // Each check is gated on its protocol prerequisite so non-applicable
  // packets cannot produce spurious anomalies.
  //
  //   [0] bad_ihl         : IPv4 IHL field < 5 (header too short to be valid)
  //   [1] tcp_syn_fin     : SYN and FIN both set in same TCP packet
  //   [2] ip_len_mismatch : IP total length disagrees with observed frame length
  // ---------------------------------------------------------------------------
  assign anomaly_bits[0] = meta.is_ipv4 && (meta.ip_ihl < 5);
  assign anomaly_bits[1] = meta.is_tcp  && meta.tcp_flags[0] && meta.tcp_flags[1];
  assign anomaly_bits[2] = meta.is_ipv4 && ((meta.ip_total_length + 14) != meta.frame_length);


  // ---------------------------------------------------------------------------
  // Priority encoder
  //
  // Find the lowest-index rule that matched. If no rule matched, rule_id
  // defaults to 0 (safe because the drop_packet expression gates this
  // lookup with a |hit_mask check).
  // ---------------------------------------------------------------------------
  always_comb begin
    rule_id = 3'd0;
    for (int i = 0; i < NUM_RULES; i++) begin
      if (hit_mask[i]) begin
        rule_id = i[2:0];
        break;
      end
    end
  end


  // ---------------------------------------------------------------------------
  // Drop decision
  //
  // Drop the packet if any anomaly fired OR if the matching rule's action
  // is "drop" (action == 3'd1). The (|hit_mask) guard prevents reading
  // rule_table[0].action when no rule actually matched.
  // ---------------------------------------------------------------------------
  assign drop_packet = (|anomaly_bits)
                    || ((|hit_mask) && (rule_table[rule_id].action == 3'd1));


  // ---------------------------------------------------------------------------
  // Output register
  //
  // verdict_valid follows meta_valid with one cycle of delay. The verdict
  // struct captures the combinational results on the cycle meta_valid
  // is high, then holds them stable for the rest of the inter-packet gap.
  // The one-cycle latency also breaks the long combinational path through
  // the comparators + priority encoder + drop logic, helping timing.
  // ---------------------------------------------------------------------------
  always_ff @(posedge aclk) begin
    if (!aresetn) begin
      verdict       <= '0;
      verdict_valid <= 1'b0;
    end else begin
      verdict_valid <= meta_valid;
      if (meta_valid) begin
        verdict.rule_hit_mask <= hit_mask;
        verdict.rule_id       <= rule_id;
        verdict.anomaly_bits  <= anomaly_bits;
        verdict.any_hit       <= |hit_mask;
        verdict.drop          <= drop_packet;
      end
    end
  end

endmodule