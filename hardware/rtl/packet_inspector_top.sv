/*
Packet Inspector Top (Pipeline Wrapper)

PURPOSE: Top-level wrapper composing the three-stage packet inspection
pipeline. Instantiates header_parser, rule_checker, and event_packer;
wires them together with named internal signals; exposes the pipeline's
external interfaces (8-bit AXI-Stream slave in, 8-bit AXI-Stream master
out with TUSER, AXI-Lite slave) to the Vivado block design and ultimately
to the ARM Cortex-A9 processing system. Contains no logic of its own --
all behavior lives in the three child modules.

INPUTS:
- aclk: clock (125 MHz target, single clock domain for the whole pipeline)
- aresetn: synchronous active-low reset, fans out to all three sub-blocks
- s_axis_*: AXI-Stream slave, packet ingress from upstream
  (axis_dwidth_converter + AXI-DMA in the block design)
- s_axil_*: AXI-Lite slave for PS register access (rule programming,
  counter reads, event FIFO drain)

OUTPUTS:
- m_axis_*: AXI-Stream master, packet egress with verdict bits in TUSER
- s_axil_*: AXI-Lite read/response signals back to the PS

INTERNAL CONNECTIONS:
- meta_w, meta_valid_w   : header_parser -> rule_checker AND event_packer
                            (rule_checker uses meta for matching;
                            event_packer uses it for event composition)
- verdict_w, verdict_valid_w : rule_checker -> event_packer
- rule_table_w           : event_packer -> rule_checker (table feedback,
                            programmed by PS, consumed every cycle)
- passthrough_*          : header_parser -> event_packer (AXI-Stream
                            byte passthrough so event_packer can attach
                            TUSER and emit downstream)

HOW IT WORKS:
Packet bytes enter on s_axis_* and pass through header_parser into the
passthrough wires (combinational, no buffering). header_parser publishes
meta and meta_valid one cycle after end-of-packet. rule_checker consumes
meta, computes hit_mask and anomalies combinationally, and emits verdict
+ verdict_valid the cycle after meta_valid. event_packer consumes both
meta and verdict, updates its counters and event FIFO, and re-emits the
byte stream on m_axis_* with TUSER attached. AXI-Lite traffic from the
PS flows directly into event_packer, where it programs rule_table (which
flows back to rule_checker) and reads counters / events.

DATA FLOW:
Bytes: s_axis -> header_parser -> passthrough -> event_packer -> m_axis
Metadata: header_parser.meta -> {rule_checker, event_packer}
Verdict: rule_checker.verdict -> event_packer
Rule table: event_packer.rule_table -> rule_checker (feedback loop)

KEY DESIGN DECISIONS:
1. **No logic in the wrapper.** This file is pure structural composition.
   All packet-processing behavior is in the three child modules. The
   wrapper exists only to draw the box around them and expose the
   external interfaces.

2. **`_w` suffix on internal wires.** Distinguishes the wires that connect
   sub-blocks from the top-level port signals, even when names would
   otherwise collide (e.g., the top-level `s_axis_tdata` port vs an
   internal `tdata` wire). Avoids name shadowing.

3. **Single clock domain.** Everything runs on aclk. No CDC primitives.
   The Vivado block design configures the PS PL clock to match.

4. **8-bit AXI-Stream at the wrapper boundary.** The 64-bit DMA stream
   is adapted down by an axis_dwidth_converter IP block in the Vivado
   block design, OUTSIDE this wrapper. Keeps the RTL byte-oriented
   throughout.

5. **AXI-Lite passes through to event_packer unchanged.** event_packer
   is the only block that talks to the PS. header_parser and rule_checker
   have no PS-facing interfaces.

EDGE CASES:
- aresetn fans out as-is to all three sub-blocks; their internal
  synchronous reset handling ensures clean startup.
- The passthrough_tready signal is currently ignored downstream
  (header_parser hardcodes m_axis_tready effectively to 1 by not
  consuming it, and event_packer hardcodes s_axis_tready to 1).
  Backpressure can be wired through later without changing this file.
*/

import packet_inspector_pkg::*;

module packet_inspector_top (
  input  logic        aclk,
  input  logic        aresetn,

  // AXI-Stream slave (packet ingress, 8 bits per beat, network byte order)
  input  logic [7:0]  s_axis_tdata,
  input  logic        s_axis_tvalid,
  output logic        s_axis_tready,
  input  logic        s_axis_tlast,

  // AXI-Stream master (packet egress with verdict bits in TUSER)
  output logic [7:0]  m_axis_tdata,
  output logic        m_axis_tvalid,
  input  logic        m_axis_tready,
  output logic        m_axis_tlast,
  output logic [3:0]  m_axis_tuser,

  // AXI-Lite slave: read channel
  input  logic [11:0] s_axil_araddr,
  input  logic        s_axil_arvalid,
  output logic        s_axil_arready,
  output logic [31:0] s_axil_rdata,
  output logic [1:0]  s_axil_rresp,
  output logic        s_axil_rvalid,
  input  logic        s_axil_rready,

  // AXI-Lite slave: write channel
  input  logic [11:0] s_axil_awaddr,
  input  logic        s_axil_awvalid,
  output logic        s_axil_awready,
  input  logic [31:0] s_axil_wdata,
  input  logic [3:0]  s_axil_wstrb,
  input  logic        s_axil_wvalid,
  output logic        s_axil_wready,
  output logic [1:0]  s_axil_bresp,
  output logic        s_axil_bvalid,
  input  logic        s_axil_bready
);

  // ---------------------------------------------------------------------------
  // Inter-stage wires
  //
  // _w suffix marks them as internal-wrapper wires (distinct from same-named
  // top-level ports). Each block's outputs feed the next block's inputs
  // through these signals.
  // ---------------------------------------------------------------------------
  packet_meta_t meta_w;
  logic         meta_valid_w;

  verdict_t     verdict_w;
  logic         verdict_valid_w;

  rule_entry_t  rule_table_w [NUM_RULES];

  logic [7:0]   passthrough_tdata;
  logic         passthrough_tvalid;
  logic         passthrough_tlast;
  logic         passthrough_tuser_payload_valid;
  logic         passthrough_tready;


  // ---------------------------------------------------------------------------
  // Stage 1: header_parser
  //
  // Walks the L2/L3/L4 headers, extracts fields into meta_w, and emits the
  // packet on a passthrough AXI-Stream so downstream can attach TUSER.
  // ---------------------------------------------------------------------------
  header_parser u_header_parser (
    .aclk                       (aclk),
    .aresetn                    (aresetn),

    .s_axis_tdata               (s_axis_tdata),
    .s_axis_tvalid              (s_axis_tvalid),
    .s_axis_tready              (s_axis_tready),
    .s_axis_tlast               (s_axis_tlast),

    .m_axis_tdata               (passthrough_tdata),
    .m_axis_tvalid              (passthrough_tvalid),
    .m_axis_tready              (passthrough_tready),
    .m_axis_tlast               (passthrough_tlast),
    .m_axis_tuser_payload_valid (passthrough_tuser_payload_valid),

    .meta                       (meta_w),
    .meta_valid                 (meta_valid_w)
  );


  // ---------------------------------------------------------------------------
  // Stage 2: rule_checker
  //
  // Consumes meta_w, compares against the 8-entry rule_table_w in parallel,
  // runs the 3 anomaly detectors, and emits verdict_w one cycle later.
  // ---------------------------------------------------------------------------
  rule_checker u_rule_checker (
    .aclk          (aclk),
    .aresetn       (aresetn),
    .meta          (meta_w),
    .meta_valid    (meta_valid_w),
    .rule_table    (rule_table_w),
    .verdict       (verdict_w),
    .verdict_valid (verdict_valid_w)
  );


  // ---------------------------------------------------------------------------
  // Stage 3: event_packer
  //
  // Maintains counters, captures flagged events into a 256-entry FIFO,
  // hosts the AXI-Lite slave (which both programs rule_table_w and exposes
  // counters/events to the PS), and re-emits the byte stream with verdict
  // bits attached in m_axis_tuser.
  // ---------------------------------------------------------------------------
  event_packer u_event_packer (
    .aclk                       (aclk),
    .aresetn                    (aresetn),

    .meta                       (meta_w),
    .meta_valid                 (meta_valid_w),
    .verdict                    (verdict_w),
    .verdict_valid              (verdict_valid_w),

    .s_axis_tdata               (passthrough_tdata),
    .s_axis_tvalid              (passthrough_tvalid),
    .s_axis_tlast               (passthrough_tlast),
    .s_axis_tuser_payload_valid (passthrough_tuser_payload_valid),
    .s_axis_tready              (passthrough_tready),

    .m_axis_tdata               (m_axis_tdata),
    .m_axis_tvalid              (m_axis_tvalid),
    .m_axis_tlast               (m_axis_tlast),
    .m_axis_tuser               (m_axis_tuser),
    .m_axis_tready              (m_axis_tready),

    .rule_table                 (rule_table_w),

    .s_axil_araddr              (s_axil_araddr),
    .s_axil_arvalid             (s_axil_arvalid),
    .s_axil_arready             (s_axil_arready),
    .s_axil_rdata               (s_axil_rdata),
    .s_axil_rresp               (s_axil_rresp),
    .s_axil_rvalid              (s_axil_rvalid),
    .s_axil_rready              (s_axil_rready),
    .s_axil_awaddr              (s_axil_awaddr),
    .s_axil_awvalid             (s_axil_awvalid),
    .s_axil_awready             (s_axil_awready),
    .s_axil_wdata               (s_axil_wdata),
    .s_axil_wstrb               (s_axil_wstrb),
    .s_axil_wvalid              (s_axil_wvalid),
    .s_axil_wready              (s_axil_wready),
    .s_axil_bresp               (s_axil_bresp),
    .s_axil_bvalid              (s_axil_bvalid),
    .s_axil_bready              (s_axil_bready)
  );

endmodule