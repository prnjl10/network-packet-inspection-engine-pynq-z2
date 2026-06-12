// =============================================================================
// tb_packet_inspector_top.sv
// =============================================================================
// Integration testbench for the full packet inspection pipeline.
// =============================================================================

`timescale 1ns/1ps

import packet_inspector_pkg::*;

module tb_packet_inspector_top;

  // ---------------------------------------------------------------------------
  // Clock and reset
  // ---------------------------------------------------------------------------
  logic aclk = 0;
  logic aresetn = 0;
  always #4 aclk = ~aclk;  // 125 MHz

  // ---------------------------------------------------------------------------
  // DUT signals
  // ---------------------------------------------------------------------------
  logic [7:0]  s_axis_tdata;
  logic        s_axis_tvalid;
  logic        s_axis_tready;
  logic        s_axis_tlast;

  logic [7:0]  m_axis_tdata;
  logic        m_axis_tvalid;
  logic        m_axis_tready;
  logic        m_axis_tlast;
  logic [3:0]  m_axis_tuser;

  logic [11:0] s_axil_araddr;
  logic        s_axil_arvalid;
  logic        s_axil_arready;
  logic [31:0] s_axil_rdata;
  logic [1:0]  s_axil_rresp;
  logic        s_axil_rvalid;
  logic        s_axil_rready;

  logic [11:0] s_axil_awaddr;
  logic        s_axil_awvalid;
  logic        s_axil_awready;
  logic [31:0] s_axil_wdata;
  logic [3:0]  s_axil_wstrb;
  logic        s_axil_wvalid;
  logic        s_axil_wready;
  logic [1:0]  s_axil_bresp;
  logic        s_axil_bvalid;
  logic        s_axil_bready;

  // ---------------------------------------------------------------------------
  // DUT
  // ---------------------------------------------------------------------------
  packet_inspector_top u_dut (
    .aclk           (aclk),
    .aresetn        (aresetn),

    .s_axis_tdata   (s_axis_tdata),
    .s_axis_tvalid  (s_axis_tvalid),
    .s_axis_tready  (s_axis_tready),
    .s_axis_tlast   (s_axis_tlast),

    .m_axis_tdata   (m_axis_tdata),
    .m_axis_tvalid  (m_axis_tvalid),
    .m_axis_tready  (m_axis_tready),
    .m_axis_tlast   (m_axis_tlast),
    .m_axis_tuser   (m_axis_tuser),

    .s_axil_araddr  (s_axil_araddr),
    .s_axil_arvalid (s_axil_arvalid),
    .s_axil_arready (s_axil_arready),
    .s_axil_rdata   (s_axil_rdata),
    .s_axil_rresp   (s_axil_rresp),
    .s_axil_rvalid  (s_axil_rvalid),
    .s_axil_rready  (s_axil_rready),

    .s_axil_awaddr  (s_axil_awaddr),
    .s_axil_awvalid (s_axil_awvalid),
    .s_axil_awready (s_axil_awready),
    .s_axil_wdata   (s_axil_wdata),
    .s_axil_wstrb   (s_axil_wstrb),
    .s_axil_wvalid  (s_axil_wvalid),
    .s_axil_wready  (s_axil_wready),
    .s_axil_bresp   (s_axil_bresp),
    .s_axil_bvalid  (s_axil_bvalid),
    .s_axil_bready  (s_axil_bready)
  );

  // ---------------------------------------------------------------------------
  // drive_packet -- byte array onto s_axis, one byte per cycle, TLAST last.
  // ---------------------------------------------------------------------------
  task drive_packet(input logic [7:0] data[]);
    for (int i = 0; i < data.size(); i++) begin
      @(posedge aclk);
      s_axis_tdata  <= data[i];
      s_axis_tvalid <= 1'b1;
      s_axis_tlast  <= (i == data.size() - 1);
    end
    @(posedge aclk);
    s_axis_tvalid <= 1'b0;
    s_axis_tlast  <= 1'b0;
    s_axis_tdata  <= 8'h00;
  endtask

  // ---------------------------------------------------------------------------
  // axil_read -- single 32-bit AXI-Lite read
  //
  // Handshake pattern: drive AR, wait for ARREADY, then drive RREADY,
  // wait for RVALID, capture RDATA.
  // ---------------------------------------------------------------------------
  task axil_read(input logic [11:0] addr, output logic [31:0] data);
    // Step 1: present address and assert ARVALID
    @(posedge aclk);
    s_axil_araddr  <= addr;
    s_axil_arvalid <= 1'b1;

    // Step 2: wait for slave to accept the address
    do @(posedge aclk); while (s_axil_arready != 1'b1);

    // Step 3: deassert ARVALID, assert RREADY
    s_axil_arvalid <= 1'b0;
    s_axil_rready  <= 1'b1;

    // Step 4: wait for slave to drive RVALID with the data
    do @(posedge aclk); while (s_axil_rvalid != 1'b1);

    // Step 5: capture data, deassert RREADY
    data           = s_axil_rdata;
    s_axil_rready <= 1'b0;
  endtask

  // ---------------------------------------------------------------------------
  // axil_write -- single 32-bit AXI-Lite write
  //
  // Handshake pattern: drive AW + W simultaneously, wait for AWREADY &&
  // WREADY, then drive BREADY, wait for BVALID.
  // ---------------------------------------------------------------------------
  task axil_write(input logic [11:0] addr, input logic [31:0] data);
    // Step 1: present AW and W simultaneously
    @(posedge aclk);
    s_axil_awaddr  <= addr;
    s_axil_awvalid <= 1'b1;
    s_axil_wdata   <= data;
    s_axil_wstrb   <= 4'hF;
    s_axil_wvalid  <= 1'b1;

    // Step 2: wait until both AW and W are accepted in the same cycle
    do @(posedge aclk); while (!(s_axil_awready && s_axil_wready));

    // Step 3: deassert AW and W, assert BREADY for the response
    s_axil_awvalid <= 1'b0;
    s_axil_wvalid  <= 1'b0;
    s_axil_bready  <= 1'b1;

    // Step 4: wait for write response, then deassert BREADY
    do @(posedge aclk); while (s_axil_bvalid != 1'b1);
    s_axil_bready  <= 1'b0;
  endtask
  
  // ---------------------------------------------------------------------------
  // program_rule -- write one rule table entry over 4 AXI-Lite writes.
  // Address bits: [11:7]=00001 (rule region), [6:4]=rule_idx, [3:0]=word offset.
  // ---------------------------------------------------------------------------
  task program_rule(input logic [2:0]  rule_idx,
                    input logic [31:0] src_ip,
                    input logic [31:0] dst_ip,
                    input logic [15:0] src_port,
                    input logic [15:0] dst_port,
                    input logic [7:0]  src_prefix_len,
                    input logic [7:0]  dst_prefix_len,
                    input logic [7:0]  protocol,
                    input logic [2:0]  action,
                    input logic        enable);
    axil_write({5'b00001, rule_idx, 4'h0}, src_ip);
    axil_write({5'b00001, rule_idx, 4'h4}, dst_ip);
    axil_write({5'b00001, rule_idx, 4'h8}, {src_port, dst_port});
    axil_write({5'b00001, rule_idx, 4'hC}, {src_prefix_len, dst_prefix_len,
                                            protocol, action, 4'd0, enable});
  endtask

  // ---------------------------------------------------------------------------
  // Main test sequence
  // ---------------------------------------------------------------------------
  initial begin
    logic [31:0] rdata;

    // Initialize everything we drive
    s_axis_tdata    = 8'h00;
    s_axis_tvalid   = 1'b0;
    s_axis_tlast    = 1'b0;
    m_axis_tready   = 1'b1;

    s_axil_araddr   = 12'h000;
    s_axil_arvalid  = 1'b0;
    s_axil_rready   = 1'b0;

    s_axil_awaddr   = 12'h000;
    s_axil_awvalid  = 1'b0;
    s_axil_wdata    = 32'h0;
    s_axil_wstrb    = 4'hF;
    s_axil_wvalid   = 1'b0;
    s_axil_bready   = 1'b0;

    // Reset
    aresetn = 1'b0;
    repeat (10) @(posedge aclk);
    aresetn = 1'b1;
    repeat (5) @(posedge aclk);

    // =========================================================================
    // Test 1 -- VERSION register reads as 0xDEADBEEF
    // =========================================================================
    axil_read(12'h000, rdata);
    if (rdata == 32'hDEADBEEF)
      $display("[PASS] Test 1: VERSION = %h", rdata);
    else
      $display("[FAIL] Test 1: VERSION = %h (expected DEADBEEF)", rdata);

    // =========================================================================
    // Test 2 -- write/read-back a rule table register
    //
    // Rule 0 word 0 lives at 0x080 (rule table base). Write a known
    // pattern and read it back to prove the write path is wired up.
    // NOTE: only the rule_table storage in event_packer is readable here
    //       indirectly via downstream behavior -- the rule table itself
    //       is NOT exposed on the read decoder in event_packer's v1.
    //       So we can't read it back directly; instead we'll verify the
    //       write path via observable side effects in later tests.
    //       For now, just exercise the write handshake and confirm BVALID
    //       comes back.
    // =========================================================================
    axil_write(12'h080, 32'hC0A80105);  // 192.168.1.5 (rule 0 src_ip)
    $display("[INFO] Test 2: axil_write to 0x080 completed (BVALID accepted)");

    // =========================================================================
    // Test 3 -- drive a packet, verify PACKET_COUNT increments
    // =========================================================================
    begin
      logic [7:0] pkt[];
      pkt = new[54];

      // Ethernet header
      pkt[0]=8'hAA; pkt[1]=8'hBB; pkt[2]=8'hCC; pkt[3]=8'hDD; pkt[4]=8'hEE; pkt[5]=8'hFF;
      pkt[6]=8'h11; pkt[7]=8'h22; pkt[8]=8'h33; pkt[9]=8'h44; pkt[10]=8'h55; pkt[11]=8'h66;
      pkt[12]=8'h08; pkt[13]=8'h00;
      // IPv4 header
      pkt[14]=8'h45; pkt[15]=8'h00;
      pkt[16]=8'h00; pkt[17]=8'h28;
      pkt[18]=8'h00; pkt[19]=8'h00;
      pkt[20]=8'h00; pkt[21]=8'h00;
      pkt[22]=8'h40; pkt[23]=8'h06;
      pkt[24]=8'h00; pkt[25]=8'h00;
      pkt[26]=8'hC0; pkt[27]=8'hA8; pkt[28]=8'h01; pkt[29]=8'h0A;   // src 192.168.1.10
      pkt[30]=8'hC0; pkt[31]=8'hA8; pkt[32]=8'h01; pkt[33]=8'h14;   // dst 192.168.1.20
      // TCP header
      pkt[34]=8'hC3; pkt[35]=8'h50;   // src port 50000
      pkt[36]=8'h00; pkt[37]=8'h50;   // dst port 80
      pkt[38]=8'h00; pkt[39]=8'h00; pkt[40]=8'h00; pkt[41]=8'h00;
      pkt[42]=8'h00; pkt[43]=8'h00; pkt[44]=8'h00; pkt[45]=8'h00;
      pkt[46]=8'h50; pkt[47]=8'h02;   // flags = SYN
      pkt[48]=8'h20; pkt[49]=8'h00;
      pkt[50]=8'h00; pkt[51]=8'h00;
      pkt[52]=8'h00; pkt[53]=8'h00;

      drive_packet(pkt);

      // Let the pipeline propagate (parser -> checker -> packer)
      repeat (10) @(posedge aclk);

      // Read PACKET_COUNT
      axil_read(12'h008, rdata);
      if (rdata == 32'h0000_0001)
        $display("[PASS] Test 3: PACKET_COUNT = %0d", rdata);
      else
        $display("[FAIL] Test 3: PACKET_COUNT = %0d (expected 1)", rdata);
    end
    
    // =========================================================================
    // Test 4 -- rule programming round-trip
    //
    // Program rule 0 to DROP any TCP packet with dst port 80 (wildcard
    // everything else: IPs via prefix_len=0, src port via port=0).
    // Drive the Test 3 packet again. Expect:
    //   PACKET_COUNT     == 2  (Test 3's packet + this one)
    //   DROP_COUNT       == 1
    //   RULE_HIT_COUNT[0] == 1
    // =========================================================================
    begin
      logic [7:0] pkt2[];

      program_rule(.rule_idx       (3'd0),
                   .src_ip         (32'h0000_0000),
                   .dst_ip         (32'h0000_0000),
                   .src_port       (16'h0000),
                   .dst_port       (16'h0050),   // port 80
                   .src_prefix_len (8'h00),       // wildcard
                   .dst_prefix_len (8'h00),       // wildcard
                   .protocol       (8'h06),       // TCP
                   .action         (3'd1),        // drop
                   .enable         (1'b1));

      // Same 54-byte IPv4/TCP SYN packet as Test 3
      pkt2 = new[54];
      pkt2[0]=8'hAA; pkt2[1]=8'hBB; pkt2[2]=8'hCC; pkt2[3]=8'hDD; pkt2[4]=8'hEE; pkt2[5]=8'hFF;
      pkt2[6]=8'h11; pkt2[7]=8'h22; pkt2[8]=8'h33; pkt2[9]=8'h44; pkt2[10]=8'h55; pkt2[11]=8'h66;
      pkt2[12]=8'h08; pkt2[13]=8'h00;
      pkt2[14]=8'h45; pkt2[15]=8'h00;
      pkt2[16]=8'h00; pkt2[17]=8'h28;
      pkt2[18]=8'h00; pkt2[19]=8'h00;
      pkt2[20]=8'h00; pkt2[21]=8'h00;
      pkt2[22]=8'h40; pkt2[23]=8'h06;
      pkt2[24]=8'h00; pkt2[25]=8'h00;
      pkt2[26]=8'hC0; pkt2[27]=8'hA8; pkt2[28]=8'h01; pkt2[29]=8'h0A;
      pkt2[30]=8'hC0; pkt2[31]=8'hA8; pkt2[32]=8'h01; pkt2[33]=8'h14;
      pkt2[34]=8'hC3; pkt2[35]=8'h50;
      pkt2[36]=8'h00; pkt2[37]=8'h50;
      pkt2[38]=8'h00; pkt2[39]=8'h00; pkt2[40]=8'h00; pkt2[41]=8'h00;
      pkt2[42]=8'h00; pkt2[43]=8'h00; pkt2[44]=8'h00; pkt2[45]=8'h00;
      pkt2[46]=8'h50; pkt2[47]=8'h02;
      pkt2[48]=8'h20; pkt2[49]=8'h00;
      pkt2[50]=8'h00; pkt2[51]=8'h00;
      pkt2[52]=8'h00; pkt2[53]=8'h00;

      drive_packet(pkt2);
      repeat (10) @(posedge aclk);

      axil_read(12'h008, rdata);
      if (rdata == 32'h0000_0002)
        $display("[PASS] Test 4: PACKET_COUNT = %0d", rdata);
      else
        $display("[FAIL] Test 4: PACKET_COUNT = %0d (expected 2)", rdata);

      axil_read(12'h00C, rdata);
      if (rdata == 32'h0000_0001)
        $display("[PASS] Test 4: DROP_COUNT = %0d", rdata);
      else
        $display("[FAIL] Test 4: DROP_COUNT = %0d (expected 1)", rdata);

      axil_read(12'h020, rdata);
      if (rdata == 32'h0000_0001)
        $display("[PASS] Test 4: RULE_HIT_COUNT[0] = %0d", rdata);
      else
        $display("[FAIL] Test 4: RULE_HIT_COUNT[0] = %0d (expected 1)", rdata);
    end
    repeat (20) @(posedge aclk);
    $display("Simulation complete.");
    $finish;
  end

endmodule