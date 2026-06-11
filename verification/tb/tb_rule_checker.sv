// =============================================================================
// tb_rule_checker.sv
// =============================================================================
// Directed testbench for rule_checker.
// Drives crafted packet_meta_t bundles and rule tables into the DUT and
// checks that the verdict output matches expected values.
// =============================================================================

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
  // Clock: 125 MHz = 8 ns period
  // ---------------------------------------------------------------------------
  initial begin
    aclk = 0;
    forever #4 aclk = ~aclk;
  end


  // ===========================================================================
  // TODO 1: drive_meta task    <-- DO THIS FIRST
  // ===========================================================================
  // This task takes a packet_meta_t value, drives it onto the DUT's meta
  // input, and pulses meta_valid for exactly one clock cycle.
  //
  // Skeleton:
  //   task drive_meta(input packet_meta_t m);
  //     @(posedge aclk);
  //     // TODO: assign m to the meta signal, set meta_valid <= 1
  //     @(posedge aclk);
  //     // TODO: deassert meta_valid (back to 0)
  //   endtask
  //
  // Use non-blocking <= as before. The meta value can stay assigned after
  // the pulse - only meta_valid needs to drop. The DUT samples meta only
  // when meta_valid is high.
  // ===========================================================================

  // TODO 1: write the drive_meta task here.
  task drive_meta (input packet_meta_t m);
    @(posedge aclk);
    meta <= m;
        meta_valid <= 1;
    @(posedge aclk);
        meta_valid <= 0;
  endtask


  // ===========================================================================
  // TODO 2: check_verdict task    <-- AFTER TODO 1
  // ===========================================================================
  // Compare the live verdict against an expected verdict_t. Increment
  // tests_run and tests_passed appropriately. Pattern same as check_meta:
  // one if-block per field, [FAIL] message on mismatch, [PASS] if all good.
  //
  // Fields to check: rule_hit_mask, rule_id, anomaly_bits, any_hit, drop
  //
  // Skeleton coming after TODO 1.
  // ===========================================================================

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

    // TODO: add same pattern for: rule_id, anomaly_bits, any_hit, drop

    if (pass) begin
      tests_passed++;
      $display("[PASS] %s", test_name);
    end
  endtask



  // ===========================================================================
  // TODO 3: main test sequence    <-- AFTER TODO 2
  // ===========================================================================
  // initial begin
  //   reset
  //   configure rule_table
  //   drive test 1 (allow rule hit), check
  //   drive test 2 (anomaly), check
  //   summary + $finish
  // end
  //
  // Skeleton coming after TODO 2.
  // ===========================================================================

  // ===========================================================================
  // Main test sequence
  // ===========================================================================
  initial begin

    // -------------------------------------------------------------------------
    // Test data (constructed at declaration time)
    // -------------------------------------------------------------------------

    // Test 1 input: clean TCP SYN, 192.168.1.5:54321 -> 8.8.8.8:80
    packet_meta_t meta_tcp_match = '{
      eth_dst_mac     : 48'hAABBCCDDEEFF,
      eth_src_mac     : 48'h112233445566,
      eth_type        : 16'h0800,
      ip_version      : 4'h4,
      ip_ihl          : 4'h5,
      ip_total_length : 16'h0028,        // 40
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

    // Test 1 expected: rule 0 hits, no anomaly, no drop
    verdict_t expected_match = '{
      rule_hit_mask : 8'b00000001,
      rule_id       : 3'd0,
      anomaly_bits  : 3'b000,
      any_hit       : 1'b1,
      drop          : 1'b0
    };

    // Test 2 input: same packet, but with SYN+FIN flags set (anomaly)
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
      tcp_flags       : 8'h03,           // SYN+FIN (illegal)
      frame_length    : 16'd54,
      payload_offset  : 16'd54,
      is_ipv4         : 1'b1,
      is_tcp          : 1'b1,
      is_udp          : 1'b0,
      parser_error    : 1'b0
    };

    // Test 2 expected: rule still hits (IPs match), anomaly fires, drop=1
    verdict_t expected_syn_fin = '{
      rule_hit_mask : 8'b00000001,
      rule_id       : 3'd0,
      anomaly_bits  : 3'b010,            // tcp_syn_fin bit
      any_hit       : 1'b1,
      drop          : 1'b1               // anomaly forces drop
    };


    // -------------------------------------------------------------------------
    // TODO 3a: Initialize DUT inputs to safe defaults and assert reset.
    //   - meta_valid <= 0
    //   - aresetn    <= 0
    //   - Clear the entire rule table: foreach (rule_table[i]) rule_table[i] <= '0;
    // -------------------------------------------------------------------------
    meta_valid <= 0;
    aresetn <= 0;
    foreach (rule_table[i]) rule_table[i] <= '0;

    // -------------------------------------------------------------------------
    // TODO 3b: Hold reset low for 5 cycles, then release.
    //   - repeat(5) @(posedge aclk);
    //   - aresetn <= 1;
    //   - @(posedge aclk);
    // -------------------------------------------------------------------------
    repeat(5) @(posedge aclk);
    aresetn <= 1;
    @(posedge aclk);
   


    // -------------------------------------------------------------------------
    // TODO 3c: Configure rule 0 to match TCP traffic from 192.168.1.0/24
    // to 8.8.8.0/24:80. Use a struct literal:
    //
    //   rule_table[0] = '{
    //     src_ip         : 32'hC0A80100,   // 192.168.1.0
    //     dst_ip         : 32'h08080800,   // 8.8.8.0
    //     src_port       : 16'h0000,       // wildcard
    //     dst_port       : 16'h0050,       // 80
    //     src_prefix_len : 8'd24,
    //     dst_prefix_len : 8'd24,
    //     protocol       : IP_PROTO_TCP,
    //     action         : 3'd0,           // accept
    //     reserved       : 4'd0,
    //     enable         : 1'b1
    //   };
    // -------------------------------------------------------------------------
    rule_table[0] = '{
         src_ip         : 32'hC0A80100,   // 192.168.1.0
         dst_ip         : 32'h08080800,   // 8.8.8.0
        src_port       : 16'h0000,       // wildcard
         dst_port       : 16'h0050,       // 80
        src_prefix_len : 8'd24,
        dst_prefix_len : 8'd24,
        protocol       : IP_PROTO_TCP,
         action         : 3'd0,           // accept
         reserved       : 4'd0,
         enable         : 1'b1   };


    // -------------------------------------------------------------------------
    // TODO 3d: Run Test 1.
    //   - drive_meta(meta_tcp_match);
    //   - @(posedge verdict_valid);
    //   - @(posedge aclk);
    //   - check_verdict("Test 1: TCP match accept", expected_match);
    // -------------------------------------------------------------------------
    drive_meta(meta_tcp_match);
    @(posedge verdict_valid);
    @(posedge aclk);
    check_verdict("Test 1: TCP match accept", expected_match);


    // -------------------------------------------------------------------------
    // TODO 3e: Run Test 2.
    //   - drive_meta(meta_syn_fin);
    //   - @(posedge verdict_valid);
    //   - @(posedge aclk);
    //   - check_verdict("Test 2: TCP SYN+FIN anomaly", expected_syn_fin);
    // -------------------------------------------------------------------------
    drive_meta(meta_syn_fin);
    @(posedge verdict_valid);
    @(posedge aclk);
    check_verdict("Test 2: TCP SYN+FIN anomaly", expected_syn_fin);


    // -------------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------------
    $display("");
    $display("==============================================");
    $display("  Tests: %0d passed / %0d run", tests_passed, tests_run);
    $display("==============================================");
    $finish;
  end


endmodule