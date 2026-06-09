// =============================================================================
// tb_header_parser.sv
// =============================================================================
// Directed testbench for header_parser.
//
// Drives crafted Ethernet frames into the parser one byte per clock and
// compares the captured metadata bundle against hand-computed expected
// values. Each test case lives as a byte array + expected packet_meta_t
// pair inside the main initial block. Pass/fail is reported per-test and
// counted in tests_run / tests_passed for a final summary.
// =============================================================================

`timescale 1ns / 1ps

import packet_inspector_pkg::*;

module tb_header_parser;

  // ---------------------------------------------------------------------------
  // DUT-facing signals
  // ---------------------------------------------------------------------------
  logic         aclk;
  logic         aresetn;

  // Input side (testbench drives these)
  logic [7:0]   s_axis_tdata;
  logic         s_axis_tvalid;
  logic         s_axis_tlast;

  // Output side (testbench observes these)
  logic         s_axis_tready;
  logic [7:0]   m_axis_tdata;
  logic         m_axis_tvalid;
  logic         m_axis_tlast;
  logic         m_axis_tready;
  logic         m_axis_tuser_payload_valid;
  packet_meta_t meta;
  logic         meta_valid;

  // Per-run test statistics
  int tests_run    = 0;
  int tests_passed = 0;


  // ---------------------------------------------------------------------------
  // DUT instantiation
  // ---------------------------------------------------------------------------
  header_parser dut (
    .aclk                       (aclk),
    .aresetn                    (aresetn),
    .s_axis_tdata               (s_axis_tdata),
    .s_axis_tvalid              (s_axis_tvalid),
    .s_axis_tready              (s_axis_tready),
    .s_axis_tlast               (s_axis_tlast),
    .m_axis_tdata               (m_axis_tdata),
    .m_axis_tvalid              (m_axis_tvalid),
    .m_axis_tready              (m_axis_tready),
    .m_axis_tlast               (m_axis_tlast),
    .m_axis_tuser_payload_valid (m_axis_tuser_payload_valid),
    .meta                       (meta),
    .meta_valid                 (meta_valid)
  );

  // Always accept the parser's passthrough output -- no backpressure modeled
  // on the testbench side.
  assign m_axis_tready = 1'b1;


  // ---------------------------------------------------------------------------
  // Clock generator: 125 MHz = 8 ns period
  // ---------------------------------------------------------------------------
  initial begin
    aclk = 0;
    forever #4 aclk = ~aclk;       // 4 ns half-period -> 8 ns period
  end


  // ---------------------------------------------------------------------------
  // drive_packet
  //
  // Stream a packet (unpacked byte array) through the parser's input AXIS
  // port, one byte per clock. Asserts TLAST on the final beat. Deasserts
  // TVALID/TLAST one cycle after the last byte so the parser sees an idle
  // gap before the next packet.
  // ---------------------------------------------------------------------------
  task drive_packet(input bit [7:0] packet[]);
    int len = packet.size();
    for (int i = 0; i < len; i++) begin
      @(posedge aclk);
      s_axis_tdata  <= packet[i];
      s_axis_tvalid <= 1;
      s_axis_tlast  <= (i == len - 1);
    end
    @(posedge aclk);
    s_axis_tvalid <= 0;
    s_axis_tlast  <= 0;
  endtask


  // ---------------------------------------------------------------------------
  // check_meta
  //
  // Field-by-field compare of the live `meta` bundle against an expected
  // packet_meta_t. Increments tests_run unconditionally; only increments
  // tests_passed and prints [PASS] if every checked field matches. On any
  // mismatch, prints a [FAIL] line per offending field so debugging shows
  // which specific value diverged.
  // ---------------------------------------------------------------------------
  task check_meta(input string test_name, input packet_meta_t expected);
    bit pass = 1'b1;
    tests_run++;

    if (meta.eth_dst_mac !== expected.eth_dst_mac) begin
      $display("[FAIL] %s: eth_dst_mac expected %h, got %h",
               test_name, expected.eth_dst_mac, meta.eth_dst_mac);
      pass = 1'b0;
    end

    if (meta.eth_src_mac !== expected.eth_src_mac) begin
      $display("[FAIL] %s: eth_src_mac expected %h, got %h",
               test_name, expected.eth_src_mac, meta.eth_src_mac);
      pass = 1'b0;
    end

    if (meta.eth_type !== expected.eth_type) begin
      $display("[FAIL] %s: eth_type expected %h, got %h",
               test_name, expected.eth_type, meta.eth_type);
      pass = 1'b0;
    end

    if (meta.ip_src !== expected.ip_src) begin
      $display("[FAIL] %s: ip_src expected %h, got %h",
               test_name, expected.ip_src, meta.ip_src);
      pass = 1'b0;
    end

    if (meta.ip_dst !== expected.ip_dst) begin
      $display("[FAIL] %s: ip_dst expected %h, got %h",
               test_name, expected.ip_dst, meta.ip_dst);
      pass = 1'b0;
    end

    if (meta.ip_protocol !== expected.ip_protocol) begin
      $display("[FAIL] %s: ip_protocol expected %h, got %h",
               test_name, expected.ip_protocol, meta.ip_protocol);
      pass = 1'b0;
    end

    if (meta.l4_src_port !== expected.l4_src_port) begin
      $display("[FAIL] %s: l4_src_port expected %h, got %h",
               test_name, expected.l4_src_port, meta.l4_src_port);
      pass = 1'b0;
    end

    if (meta.l4_dst_port !== expected.l4_dst_port) begin
      $display("[FAIL] %s: l4_dst_port expected %h, got %h",
               test_name, expected.l4_dst_port, meta.l4_dst_port);
      pass = 1'b0;
    end

    if (meta.tcp_flags !== expected.tcp_flags) begin
      $display("[FAIL] %s: tcp_flags expected %h, got %h",
               test_name, expected.tcp_flags, meta.tcp_flags);
      pass = 1'b0;
    end

    if (meta.frame_length !== expected.frame_length) begin
      $display("[FAIL] %s: frame_length expected %h, got %h",
               test_name, expected.frame_length, meta.frame_length);
      pass = 1'b0;
    end

    if (meta.is_ipv4 !== expected.is_ipv4) begin
      $display("[FAIL] %s: is_ipv4 expected %h, got %h",
               test_name, expected.is_ipv4, meta.is_ipv4);
      pass = 1'b0;
    end

    if (meta.is_tcp !== expected.is_tcp) begin
      $display("[FAIL] %s: is_tcp expected %h, got %h",
               test_name, expected.is_tcp, meta.is_tcp);
      pass = 1'b0;
    end

    if (meta.is_udp !== expected.is_udp) begin
      $display("[FAIL] %s: is_udp expected %h, got %h",
               test_name, expected.is_udp, meta.is_udp);
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
    // Test 1: clean IPv4 / TCP SYN to port 80
    //
    // 54-byte packet. Standard well-formed frame with all headers present.
    // Exercises: Ethernet capture, IPv4 capture, TCP capture, the derived
    // flags (is_ipv4 / is_tcp / is_udp), and payload_offset computation.
    //
    //   Bytes  0-5    Dst MAC      AA:BB:CC:DD:EE:FF
    //   Bytes  6-11   Src MAC      11:22:33:44:55:66
    //   Bytes 12-13   EtherType    0x0800 (IPv4)
    //   Byte  14      Version+IHL  0x45 (v4, IHL=5)
    //   Byte  15      ToS          0x00
    //   Bytes 16-17   TotalLen     0x0028 (40)
    //   Bytes 18-19   ID           0x0000
    //   Bytes 20-21   Flags+Frag   0x4000 (DF)
    //   Byte  22      TTL          0x40 (64)
    //   Byte  23      Protocol     0x06 (TCP)
    //   Bytes 24-25   Checksum     0x0000
    //   Bytes 26-29   Src IP       192.168.1.5
    //   Bytes 30-33   Dst IP       8.8.8.8
    //   Bytes 34-35   Src Port     0xD431 (54321)
    //   Bytes 36-37   Dst Port     0x0050 (80)
    //   Bytes 38-45   Seq + Ack    all zeros
    //   Byte  46      DataOffset   0x50
    //   Byte  47      TCP Flags    0x02 (SYN only)
    //   Bytes 48-49   Window       0x2000
    //   Bytes 50-53   Checksum + UrgPtr  zeros
    // -------------------------------------------------------------------------
    bit [7:0] tcp_syn_packet [54] = '{
      // Ethernet
      8'hAA, 8'hBB, 8'hCC, 8'hDD, 8'hEE, 8'hFF,
      8'h11, 8'h22, 8'h33, 8'h44, 8'h55, 8'h66,
      8'h08, 8'h00,
      // IPv4
      8'h45, 8'h00, 8'h00, 8'h28, 8'h00, 8'h00,
      8'h40, 8'h00, 8'h40, 8'h06, 8'h00, 8'h00,
      8'hC0, 8'hA8, 8'h01, 8'h05,
      8'h08, 8'h08, 8'h08, 8'h08,
      // TCP
      8'hD4, 8'h31, 8'h00, 8'h50,
      8'h00, 8'h00, 8'h00, 8'h00,
      8'h00, 8'h00, 8'h00, 8'h00,
      8'h50, 8'h02, 8'h20, 8'h00,
      8'h00, 8'h00, 8'h00, 8'h00
    };

    packet_meta_t expected_tcp_syn;
    expected_tcp_syn = '{
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
      tcp_flags       : 8'h02,
      frame_length    : 16'd54,
      payload_offset  : 16'd54,
      is_ipv4         : 1'b1,
      is_tcp          : 1'b1,
      is_udp          : 1'b0,
      parser_error    : 1'b0
    };

    // Initialize all DUT inputs to known-quiet values and assert reset.
    s_axis_tdata  <= 0;
    s_axis_tvalid <= 0;
    s_axis_tlast  <= 0;
    aresetn       <= 0;

    // Hold reset low for a handful of clocks, then release synchronously.
    repeat (5) @(posedge aclk);
    aresetn <= 1;
    @(posedge aclk);

    // Drive Test 1, wait for the parser to publish meta, then check.
    drive_packet(tcp_syn_packet);
    @(posedge meta_valid);
    @(posedge aclk);
    check_meta("Test 1: IPv4/TCP SYN", expected_tcp_syn);

    // Final summary
    $display("");
    $display("==============================================");
    $display("  Tests: %0d passed / %0d run", tests_passed, tests_run);
    $display("==============================================");

    $finish;
  end

endmodule