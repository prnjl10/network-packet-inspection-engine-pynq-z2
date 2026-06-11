/*
Rule Checker Testbench

PURPOSE: Directed testbench for rule_checker. Validates that the parallel
rule comparison, anomaly detection, priority encoding, and drop decision
all behave correctly by driving crafted packet_meta_t bundles and
rule_table configurations into the DUT and comparing the resulting
verdict against pre-computed expected values.

DUT INPUTS (driven by testbench):
- aclk: 125 MHz clock generated locally
- aresetn: held low for 5 cycles then released synchronously
- meta [packet_meta_t]: pre-constructed metadata bundles, one per test case
- meta_valid: pulsed for exactly one cycle by drive_meta
- rule_table [NUM_RULES]: 8-entry rule table populated before any tests
  drive packets

DUT OUTPUTS (observed by testbench):
- verdict [verdict_t]: rule_hit_mask, rule_id, anomaly_bits, any_hit, drop
- verdict_valid: pulses one cycle after meta_valid

INTERNAL STATE (testbench):
- tests_run, tests_passed: 32-bit counters incremented by check_verdict.
  Final summary prints "passed / run" at $finish time.
- meta, meta_valid, rule_table: driven combinationally onto the DUT.
- verdict, verdict_valid: observed only; never written by the testbench.

HOW IT WORKS:
After standard reset (aresetn low for 5 cycles, then released), the
testbench configures rule[0] to match TCP traffic from 192.168.1.0/24 to
8.8.8.0/24:80 with the "accept" action. The remaining 7 rules are left
zero-initialized (disabled by their enable bit).

Each test case is a (meta, expected_verdict) pair. drive_meta loads meta
and pulses meta_valid for one cycle. The testbench then waits for
verdict_valid (which arrives one cycle later by the DUT's design) and
calls check_verdict to compare each field of the actual verdict against
the expected. Mismatches print [FAIL] with the field name and both
values; complete success prints a single [PASS] per test.

DATA FLOW:
meta and rule_table are driven directly into the DUT's combinational
inputs. The DUT's combinational network settles within the meta_valid
cycle; the verdict is registered on the next clock edge. The testbench
observes verdict_valid as a pulse, samples the verdict outputs, and runs
the field comparison.

KEY DESIGN DECISIONS:
1. **Directed tests, not constrained-random.** Phase 1's goal is to prove
   each code path works at all, not to cover the full input space. Two
   hand-crafted packets exercise both the rule-match path and the
   anomaly-override path, which is enough for the sprint timeline.
   Constrained-random / coverage closure is documented as future work.

2. **Struct literal initialization at declaration time.** SystemVerilog's
   '{field: value} syntax constructs the meta and expected_verdict
   bundles in one block per test case. More readable than 18 separate
   assignments and makes the test inputs self-documenting.

3. **One rule configured, seven cleared.** Test 1 verifies rule[0] hits;
   the cleared rules confirm that disabled rules don't spuriously match.
   This also documents the expected initialization pattern for software.

4. **Anomaly-override test as a separate case.** Test 2 deliberately
   uses the SAME packet as Test 1 (matching rule 0) but flips tcp_flags
   to SYN+FIN. The verdict should show rule_hit_mask=0x01 (rule still
   matches) AND anomaly_bits[1]=1 AND drop=1. This proves the drop
   decision is OR'd between anomalies and rule actions, not gated by
   "no rule matched."

TEST CASES:
- Test 1: Clean TCP SYN to port 80, matching rule 0's allow pattern.
  Expected: rule_hit_mask=0x01, rule_id=0, anomaly_bits=0, any_hit=1, drop=0.

- Test 2: Same packet, tcp_flags=0x03 (SYN+FIN).
  Expected: rule_hit_mask=0x01 (still matches), anomaly_bits[1]=1,
  any_hit=1, drop=1 (anomaly forces the drop).
*/

`timescale 1ns / 1ps

import packet_inspector_pkg::*;

module tb_rule_checker;

  // ---------------------------------------------------------------------------
  // DUT-facing signals
  // ---------------------------------------------------------------------------
  logic          aclk;
  logic          aresetn;
  packet_meta_t  meta;
  logic          meta_valid;
  rule_entry_t   rule_table [NUM_RULES];
  verdict_t      verdict;
  logic          verdict_valid;

  // Per-run test statistics
  int tests_run    = 0;
  int tests_passed = 0;


  // ---------------------------------------------------------------------------
  // DUT instantiation
  // ---------------------------------------------------------------------------
  rule_checker dut (
    .aclk         (aclk),
    .aresetn      (aresetn),
    .meta         (meta),
    .meta_valid   (meta_valid),
    .rule_table   (rule_table),
    .verdict      (verdict),
    .verdict_valid(verdict_valid)
  );


  // ---------------------------------------------------------------------------
  // Clock generator: 125 MHz = 8 ns period
  // ---------------------------------------------------------------------------
  initial begin
    aclk = 0;
    forever #4 aclk = ~aclk;
  end


  // ---------------------------------------------------------------------------
  // drive_meta
  //
  // Load a packet_meta_t bundle onto the DUT's meta input and pulse
  // meta_valid for exactly one clock cycle. The meta value remains
  // assigned after the pulse (the DUT only samples it while meta_valid
  // is high) so leftover values between tests are harmless.
  // ---------------------------------------------------------------------------
  task drive_meta(input packet_meta_t m);
    @(posedge aclk);
    meta       <= m;
    meta_valid <= 1;
    @(posedge aclk);
    meta_valid <= 0;
  endtask


  // ---------------------------------------------------------------------------
  // check_verdict
  //
  // Field-by-field compare of the live verdict against an expected
  // verdict_t. Increments tests_run unconditionally; only increments
  // tests_passed and prints [PASS] if every checked field matches.
  // Mismatched fields each print a [FAIL] line naming the field and
  // both values, so a single failed test produces one line per offender.
  // ---------------------------------------------------------------------------
  task check_verdict(input string test_name, input verdict_t expected);
    bit pass = 1'b1;
    tests_run++;

    if (verdict.rule_hit_mask !== expected.rule_hit_mask) begin
      $display("[FAIL] %s: rule_hit_mask expected %h, got %h",
               test_name, expected.rule_hit_mask, verdict.rule_hit_mask);
      pass = 1'b0;
    end

    if (verdict.rule_id !== expected.rule_id) begin
      $display("[FAIL] %s: rule_id expected %b, got %b",
               test_name, expected.rule_id, verdict.rule_id);
      pass = 1'b0;
    end

    if (verdict.anomaly_bits !== expected.anomaly_bits) begin
      $display("[FAIL] %s: anomaly_bits expected %b, got %b",
               test_name, expected.anomaly_bits, verdict.anomaly_bits);
      pass = 1'b0;
    end

    if (verdict.any_hit !== expected.any_hit) begin
      $display("[FAIL] %s: any_hit expected %b, got %b",
               test_name, expected.any_hit, verdict.any_hit);
      pass = 1'b0;
    end

    if (verdict.drop !== expected.drop) begin
      $display("[FAIL] %s: drop expected %b, got %b",
               test_name, expected.drop, verdict.drop);
      pass = 1'b0;
    end

    if (pass) begin
      tests_passed++;
      $display("[PASS] %s", test_name);
    end
  endtask


  // ===========================================================================
  // Main test sequence
  // ===========================================================================
  initial begin

    // -------------------------------------------------------------------------
    // Test 1 input: clean TCP SYN, 192.168.1.5:54321 -> 8.8.8.8:80
    // Standard well-formed packet that should match rule 0's accept pattern.
    // -------------------------------------------------------------------------
    packet_meta_t meta_tcp_match = '{
      eth_dst_mac     : 48'hAABBCCDDEEFF,
      eth_src_mac     : 48'h112233445566,
      eth_type        : 16'h0800,
      ip_version      : 4'h4,
      ip_ihl          : 4'h5,
      ip_total_length : 16'h0028,        // 40 (20-byte IP + 20-byte TCP)
      ip_protocol     : IP_PROTO_TCP,
      ip_src          : 32'hC0A80105,    // 192.168.1.5
      ip_dst          : 32'h08080808,    // 8.8.8.8
      l4_src_port     : 16'hD431,        // 54321
      l4_dst_port     : 16'h0050,        // 80
      tcp_flags       : 8'h02,           // SYN only
      frame_length    : 16'd54,
      payload_offset  : 16'd54,
      is_ipv4         : 1'b1,
      is_tcp          : 1'b1,
      is_udp          : 1'b0,
      parser_error    : 1'b0
    };

    // Test 1 expected: rule 0 hits, no anomaly, no drop.
    verdict_t expected_match = '{
      rule_hit_mask : 8'b00000001,
      rule_id       : 3'd0,
      anomaly_bits  : 3'b000,
      any_hit       : 1'b1,
      drop          : 1'b0
    };

    // -------------------------------------------------------------------------
    // Test 2 input: same packet as Test 1, but with SYN+FIN flags set.
    // Exercises the anomaly path: rule still matches on IPs/ports, but
    // the tcp_syn_fin anomaly should force a drop regardless of action.
    // -------------------------------------------------------------------------
    packet_meta_t meta_syn_fin = '{
      eth_dst_mac     : 48'hAABBCCDDEEFF,
      eth_src_mac     : 48'h112233445566,
      eth_type        : 16'h0800,
      ip_version      : 4'h4,
      ip_ihl          : 4'h5,
      ip_total_length : 16'h0028,
      ip_protocol     : IP_PROTO_TCP,
      ip_src          : 32'hC0A80105,
      ip_dst          : 32'h08080808,
      l4_src_port     : 16'hD431,
      l4_dst_port     : 16'h0050,
      tcp_flags       : 8'h03,           // SYN + FIN (illegal combination)
      frame_length    : 16'd54,
      payload_offset  : 16'd54,
      is_ipv4         : 1'b1,
      is_tcp          : 1'b1,
      is_udp          : 1'b0,
      parser_error    : 1'b0
    };

    // Test 2 expected: rule hits AND anomaly fires AND drop=1.
    verdict_t expected_syn_fin = '{
      rule_hit_mask : 8'b00000001,
      rule_id       : 3'd0,
      anomaly_bits  : 3'b010,            // tcp_syn_fin bit
      any_hit       : 1'b1,
      drop          : 1'b1               // anomaly overrides rule's accept
    };

    // Initialize DUT inputs to safe defaults and assert reset.
    meta_valid <= 0;
    aresetn    <= 0;
    foreach (rule_table[i]) rule_table[i] <= '0;

    // Hold reset low for a handful of clocks, then release.
    repeat (5) @(posedge aclk);
    aresetn <= 1;
    @(posedge aclk);

    // Configure rule 0: accept TCP traffic from 192.168.1.0/24 to
    // 8.8.8.0/24 on destination port 80. Source port is wildcarded.
    rule_table[0] = '{
      src_ip         : 32'hC0A80100,
      dst_ip         : 32'h08080800,
      src_port       : 16'h0000,         // wildcard
      dst_port       : 16'h0050,         // 80
      src_prefix_len : 8'd24,
      dst_prefix_len : 8'd24,
      protocol       : IP_PROTO_TCP,
      action         : 3'd0,             // accept
      reserved       : 4'd0,
      enable         : 1'b1
    };

    // Run Test 1: rule match, no anomaly.
    drive_meta(meta_tcp_match);
    @(posedge verdict_valid);
    @(posedge aclk);
    check_verdict("Test 1: TCP match accept", expected_match);

    // Run Test 2: same packet, anomaly forces drop.
    drive_meta(meta_syn_fin);
    @(posedge verdict_valid);
    @(posedge aclk);
    check_verdict("Test 2: TCP SYN+FIN anomaly", expected_syn_fin);

    // Summary
    $display("");
    $display("==============================================");
    $display("  Tests: %0d passed / %0d run", tests_passed, tests_run);
    $display("==============================================");
    $finish;
  end

endmodule