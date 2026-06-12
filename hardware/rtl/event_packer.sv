/*
Event Packer (Block 3 of the Packet Inspection Pipeline)

PURPOSE: Final stage of the packet inspection pipeline. The event_packer
serves four jobs: (1) maintains protocol-level counters tracking total
packets, drops, per-rule hits, and per-anomaly hits; (2) captures flagged
packets (any rule hit OR any anomaly fired) into a 256-entry FIFO for
software to drain; (3) hosts the AXI-Lite slave the ARM Cortex-A9 uses
to program rules, read counters, and pop events; and (4) attaches
verdict-derived sideband bits to TUSER on the AXI-Stream passthrough.

INPUTS:
- aclk: clock (125 MHz target)
- aresetn: synchronous active-low reset
- meta [packet_meta_t], meta_valid: parsed headers from header_parser
- verdict [verdict_t], verdict_valid: rule/anomaly result from rule_checker
- s_axis_* : AXI-Stream byte passthrough from header_parser
- s_axil_* : AXI-Lite slave channels (read + write) from the PS

OUTPUTS:
- m_axis_* : AXI-Stream passthrough with verdict bits attached in TUSER
- rule_table [NUM_RULES] : driven from internal storage, wired back to
  rule_checker
- AXI-Lite read/response signals to the PS

INTERNAL STATE:
- packet_count, drop_count: 32-bit accumulating counters.
- rule_hit_count[NUM_RULES]: 32-bit per-rule hit counters.
- anomaly_hit_count[3]: 32-bit per-anomaly hit counters.
- timestamp_counter: free-running 32-bit counter, stamped onto each
  event captured into the FIFO.
- event_fifo[EVENT_FIFO_DEPTH]: 256-entry array of event_entry_t.
- fifo_wr_ptr, fifo_rd_ptr, fifo_count: 9-bit pointers and count.
- fifo_overflow: sticky bit, set when a push hits a full FIFO.
- rule_table_storage[NUM_RULES]: AXI-Lite-writable rule table.
- tuser_reg: registered verdict bits for the TUSER sideband.

HOW IT WORKS:
The four subsystems operate independently and concurrently:

  COUNTERS. One always_ff increments packet_count on every verdict_valid;
  drop_count when verdict.drop; rule_hit_count[i] / anomaly_hit_count[j]
  when the corresponding bit of verdict is set. Per-rule and per-anomaly
  loops are unrolled at elaboration.

  EVENT FIFO. When verdict_valid AND (verdict.any_hit OR any anomaly
  bit), an event_entry_t is composed combinationally from meta + verdict
  + timestamp_counter and pushed into the FIFO. If the FIFO is full the
  push is dropped and fifo_overflow latches high. The read pointer is
  advanced by the AXI-Lite read channel when software reads the last
  word of an event (auto-pop).

  AXI-LITE SLAVE. Two independent simple slaves (read + write), each one
  cycle of latency. The read slave decodes the address combinationally
  (case statement on s_axil_araddr) and exposes counters, status, and
  the front-of-FIFO event. The write slave waits for AWVALID and WVALID
  to be high simultaneously, then writes into rule_table_storage if the
  address is in the rule-table range; non-rule writes are silently
  acknowledged.

  TUSER. tuser_reg holds the most recent verdict bits and is updated on
  every verdict_valid pulse. m_axis_tuser is a continuous assign of
  tuser_reg, so the downstream consumer always sees the latest verdict.

DATA FLOW:
Bytes flow combinationally from s_axis to m_axis (no buffering). meta
and verdict arrive from the upstream blocks at end-of-packet via their
respective valid pulses; counters and the event FIFO update on those
pulses. AXI-Lite traffic is independent and can interleave freely with
packet processing.

KEY DESIGN DECISIONS:
1. **Free-running timestamp.** A 32-bit counter incrementing every clock
   gives every event a unique time-ordered tag. Software can divide by
   the clock frequency to convert to seconds.

2. **Sticky overflow bit.** When the FIFO is full, the push is dropped
   silently but fifo_overflow latches high. Software reads STATUS to
   detect lost events. The bit is cleared only by reset -- deliberate,
   to avoid races where overflow occurs between a read-clear pair.

3. **Auto-pop on event word 4 read.** Each event spans 5 32-bit words.
   Reading word 4 (0x060) auto-advances fifo_rd_ptr, so software
   doesn't need a separate "advance" write per event. Halves the
   AXI-Lite transactions to drain the FIFO.

4. **Single-cycle AXI-Lite slaves.** Each channel responds the cycle
   after the address handshake. Simpler than a multi-state FSM and
   adequate for register-file-style access.

5. **No clock-domain crossing.** AXI-Lite runs in the same clock domain
   (aclk) as the pipeline. The PS clock is configured to match.

6. **Registered TUSER.** Verdict bits are captured in tuser_reg on each
   verdict_valid and held stable until the next packet. Downstream
   consumers see the most recent verdict reflected on every byte.

EDGE CASES:
- FIFO push into full FIFO: silently drops the event, sets fifo_overflow.
  No upstream backpressure -- the pipeline runs at full rate.
- Reads of unmapped addresses: return 0 via the case default.
- Writes to non-rule-table addresses: silently acknowledged with OKAY.
- Concurrent FIFO push and pop: the 4-way count update case handles all
  combinations (write only / read only / both / neither) correctly.
- AW and W on different cycles: NOT supported in v1; master must present
  both simultaneously. Vivado's AXI-Lite master always does this.

MEMORY MAP:
  Read side:
    0x000 VERSION       (RO, 0xDEADBEEF)
    0x004 STATUS        (RO, {overflow, full, empty, has_events})
    0x008 PACKET_COUNT  (RO)
    0x00C DROP_COUNT    (RO)
    0x010 FIFO_LEVEL    (RO, current FIFO occupancy)
    0x020..0x03C        RULE_HIT_COUNT[0..7] (RO)
    0x040..0x048        ANOMALY_HIT_COUNT[0..2] (RO)
    0x050..0x060        EVENT_WORD[0..4] (RO, 0x060 auto-pops)
  Write side:
    0x080..0x0FC        RULE_TABLE (RW, 8 rules x 4 words each)
    Other addresses     no-op writes acknowledged with OKAY
*/

import packet_inspector_pkg::*;

module event_packer (
  input  logic              aclk,
  input  logic              aresetn,

  // Metadata + verdict from upstream pipeline stages
  input  packet_meta_t      meta,
  input  logic              meta_valid,
  input  verdict_t          verdict,
  input  logic              verdict_valid,

  // Passthrough AXI-Stream (header_parser -> downstream consumer)
  input  logic [7:0]        s_axis_tdata,
  input  logic              s_axis_tvalid,
  input  logic              s_axis_tlast,
  input  logic              s_axis_tuser_payload_valid,
  output logic              s_axis_tready,

  output logic [7:0]        m_axis_tdata,
  output logic              m_axis_tvalid,
  output logic              m_axis_tlast,
  output logic [3:0]        m_axis_tuser,
  input  logic              m_axis_tready,

  // Rule table feedback to rule_checker
  output rule_entry_t       rule_table [NUM_RULES],

  // AXI-Lite slave: read channel
  input  logic [11:0]       s_axil_araddr,
  input  logic              s_axil_arvalid,
  output logic              s_axil_arready,
  output logic [31:0]       s_axil_rdata,
  output logic [1:0]        s_axil_rresp,
  output logic              s_axil_rvalid,
  input  logic              s_axil_rready,

  // AXI-Lite slave: write channel
  input  logic [11:0]       s_axil_awaddr,
  input  logic              s_axil_awvalid,
  output logic              s_axil_awready,
  input  logic [31:0]       s_axil_wdata,
  input  logic [3:0]        s_axil_wstrb,
  input  logic              s_axil_wvalid,
  output logic              s_axil_wready,
  output logic [1:0]        s_axil_bresp,
  output logic              s_axil_bvalid,
  input  logic              s_axil_bready
);

  // v1: passthrough is always ready. Downstream FIFO absorbs throughput.
  assign s_axis_tready = 1'b1;


  // ---------------------------------------------------------------------------
  // Counters
  //
  // Single always_ff that handles packet/drop/per-rule/per-anomaly counters.
  // Each accumulates on verdict_valid, gated on its trigger condition.
  // Per-rule and per-anomaly loops unroll at elaboration into parallel
  // increment logic.
  // ---------------------------------------------------------------------------
  logic [31:0] packet_count;
  logic [31:0] drop_count;
  logic [31:0] rule_hit_count    [NUM_RULES];
  logic [31:0] anomaly_hit_count [3];

  always_ff @(posedge aclk) begin
    if (!aresetn) begin
      packet_count <= 32'd0;
      drop_count   <= 32'd0;
      for (int i = 0; i < NUM_RULES; i++) rule_hit_count[i]    <= 32'd0;
      for (int j = 0; j < 3;         j++) anomaly_hit_count[j] <= 32'd0;
    end else if (verdict_valid) begin
      packet_count <= packet_count + 1;
      if (verdict.drop) drop_count <= drop_count + 1;
      for (int i = 0; i < NUM_RULES; i++) begin
        if (verdict.rule_hit_mask[i]) rule_hit_count[i] <= rule_hit_count[i] + 1;
      end
      for (int j = 0; j < 3; j++) begin
        if (verdict.anomaly_bits[j]) anomaly_hit_count[j] <= anomaly_hit_count[j] + 1;
      end
    end
  end


  // ---------------------------------------------------------------------------
  // Free-running timestamp counter
  //
  // 32-bit counter incrementing every clock. Used to time-stamp events
  // pushed into the FIFO so software can sort them temporally.
  // ---------------------------------------------------------------------------
  logic [31:0] timestamp_counter;

  always_ff @(posedge aclk) begin
    if (!aresetn)
      timestamp_counter <= 32'd0;
    else
      timestamp_counter <= timestamp_counter + 1;
  end


  // ---------------------------------------------------------------------------
  // Event composition
  //
  // Combinational packing of meta + verdict + timestamp into an
  // event_entry_t. Always alive; only pushed into the FIFO when
  // fifo_write_en is asserted below.
  // ---------------------------------------------------------------------------
  event_entry_t current_event;

  always_comb begin
    current_event.timestamp    = timestamp_counter;
    current_event.event_type   = (|verdict.anomaly_bits) ? 4'd1 : 4'd0;
    current_event.rule_id      = {1'b0, verdict.rule_id};
    current_event.anomaly_bits = verdict.anomaly_bits;
    current_event.ip_protocol  = meta.ip_protocol;
    current_event.tcp_flags    = meta.tcp_flags;
    current_event.drop         = verdict.drop;
    current_event.reserved     = 4'd0;
    current_event.src_ip       = meta.ip_src;
    current_event.dst_ip       = meta.ip_dst;
    current_event.src_port     = meta.l4_src_port;
    current_event.dst_port     = meta.l4_dst_port;
  end


  // ---------------------------------------------------------------------------
  // Event FIFO
  //
  // 256-entry FIFO using a simple BRAM-inferable register array indexed by
  // 9-bit pointers (extra bit disambiguates full vs empty when wr_ptr ==
  // rd_ptr). Pushed when verdict_valid && (rule hit OR anomaly). Popped by
  // the AXI-Lite read channel reading EVENT_WORD4 (0x060). Pushes into a
  // full FIFO drop silently and latch fifo_overflow.
  // ---------------------------------------------------------------------------
  event_entry_t  event_fifo [EVENT_FIFO_DEPTH];
  logic [8:0]    fifo_wr_ptr;
  logic [8:0]    fifo_rd_ptr;
  logic [8:0]    fifo_count;
  logic          fifo_full;
  logic          fifo_empty;
  logic          fifo_overflow;
  logic          fifo_read_en;   // driven by AXI-Lite read channel

  logic fifo_write_en;
  assign fifo_write_en = verdict_valid && (verdict.any_hit || (|verdict.anomaly_bits));

  always_ff @(posedge aclk) begin
    if (!aresetn) begin
      fifo_wr_ptr   <= 9'd0;
      fifo_rd_ptr   <= 9'd0;
      fifo_count    <= 9'd0;
      fifo_overflow <= 1'b0;
    end else begin
      // Write side
      if (fifo_write_en && !fifo_full) begin
        event_fifo[fifo_wr_ptr[7:0]] <= current_event;
        fifo_wr_ptr <= fifo_wr_ptr + 1;
      end else if (fifo_write_en && fifo_full) begin
        fifo_overflow <= 1'b1;
      end

      // Read side
      if (fifo_read_en && !fifo_empty) begin
        fifo_rd_ptr <= fifo_rd_ptr + 1;
      end

      // Count: 4-way case handles all push/pop combinations
      case ({fifo_write_en && !fifo_full, fifo_read_en && !fifo_empty})
        2'b10:   fifo_count <= fifo_count + 1;   // push only
        2'b01:   fifo_count <= fifo_count - 1;   // pop only
        default: ;                                // both or neither: no change
      endcase
    end
  end

  assign fifo_full  = (fifo_count == EVENT_FIFO_DEPTH);
  assign fifo_empty = (fifo_count == 0);


  // ---------------------------------------------------------------------------
  // Rule table storage
  //
  // Driven by AXI-Lite writes (write channel block below); fed back out to
  // rule_checker through the rule_table output port.
  // ---------------------------------------------------------------------------
  rule_entry_t rule_table_storage [NUM_RULES];
  assign rule_table = rule_table_storage;


  // ---------------------------------------------------------------------------
  // AXI-Lite read channel
  //
  // Single-cycle slave. On the AR handshake, decode the address and load
  // rdata; assert RVALID. Hold the response until the master takes it
  // (RVALID && RREADY). Reading EVENT_WORD4 (0x060) also auto-pops the
  // event FIFO via fifo_read_en.
  // ---------------------------------------------------------------------------
  always_ff @(posedge aclk) begin
    if (!aresetn) begin
      s_axil_arready <= 1'b1;
      s_axil_rvalid  <= 1'b0;
      s_axil_rresp   <= 2'b00;
      s_axil_rdata   <= 32'd0;
      fifo_read_en   <= 1'b0;
    end else begin
      fifo_read_en <= 1'b0;

      // Accept a new address when not currently responding
      if (s_axil_arvalid && s_axil_arready) begin
        s_axil_arready <= 1'b0;
        s_axil_rvalid  <= 1'b1;
        s_axil_rresp   <= 2'b00;

        case (s_axil_araddr[11:0])
          12'h000: s_axil_rdata <= 32'hDEADBEEF;
          12'h004: s_axil_rdata <= {28'd0, fifo_overflow, fifo_full,
                                    fifo_empty, |fifo_count};
          12'h008: s_axil_rdata <= packet_count;
          12'h00C: s_axil_rdata <= drop_count;
          12'h010: s_axil_rdata <= {23'd0, fifo_count};

          12'h020: s_axil_rdata <= rule_hit_count[0];
          12'h024: s_axil_rdata <= rule_hit_count[1];
          12'h028: s_axil_rdata <= rule_hit_count[2];
          12'h02C: s_axil_rdata <= rule_hit_count[3];
          12'h030: s_axil_rdata <= rule_hit_count[4];
          12'h034: s_axil_rdata <= rule_hit_count[5];
          12'h038: s_axil_rdata <= rule_hit_count[6];
          12'h03C: s_axil_rdata <= rule_hit_count[7];

          12'h040: s_axil_rdata <= anomaly_hit_count[0];
          12'h044: s_axil_rdata <= anomaly_hit_count[1];
          12'h048: s_axil_rdata <= anomaly_hit_count[2];

          12'h050: s_axil_rdata <= event_fifo[fifo_rd_ptr[7:0]].timestamp;
          12'h054: s_axil_rdata <= {16'd0,
                                    event_fifo[fifo_rd_ptr[7:0]].event_type,
                                    event_fifo[fifo_rd_ptr[7:0]].rule_id,
                                    event_fifo[fifo_rd_ptr[7:0]].anomaly_bits,
                                    event_fifo[fifo_rd_ptr[7:0]].drop};
          12'h058: s_axil_rdata <= event_fifo[fifo_rd_ptr[7:0]].src_ip;
          12'h05C: s_axil_rdata <= event_fifo[fifo_rd_ptr[7:0]].dst_ip;
          12'h060: begin
            s_axil_rdata <= {event_fifo[fifo_rd_ptr[7:0]].src_port,
                             event_fifo[fifo_rd_ptr[7:0]].dst_port};
            fifo_read_en <= 1'b1;
          end

          default: s_axil_rdata <= 32'd0;
        endcase
      end

      // Complete the response when master takes it
      if (s_axil_rvalid && s_axil_rready) begin
        s_axil_rvalid  <= 1'b0;
        s_axil_arready <= 1'b1;
      end
    end
  end


  // ---------------------------------------------------------------------------
  // AXI-Lite write channel
  //
  // Waits for AWVALID and WVALID to be high in the same cycle, accepts
  // both, performs the write (rule_table region only), then issues BVALID.
  // Writes to non-rule-table addresses are silently acknowledged with OKAY.
  //
  // Rule-table address decode:
  //   awaddr[11:7] == 5'b00001  : region match (0x080..0x0FF)
  //   awaddr[6:4]               : rule index 0..7
  //   awaddr[3:2]               : word index 0..3 within the rule
  // ---------------------------------------------------------------------------
  always_ff @(posedge aclk) begin
    if (!aresetn) begin
      s_axil_awready <= 1'b1;
      s_axil_wready  <= 1'b1;
      s_axil_bvalid  <= 1'b0;
      s_axil_bresp   <= 2'b00;
      foreach (rule_table_storage[i]) rule_table_storage[i] <= '0;
    end else begin
      if (s_axil_awvalid && s_axil_awready &&
          s_axil_wvalid  && s_axil_wready) begin

        if (s_axil_awaddr[11:7] == 5'b00001) begin
          case (s_axil_awaddr[3:2])
            2'd0: rule_table_storage[s_axil_awaddr[6:4]].src_ip <= s_axil_wdata;
            2'd1: rule_table_storage[s_axil_awaddr[6:4]].dst_ip <= s_axil_wdata;
            2'd2: begin
              rule_table_storage[s_axil_awaddr[6:4]].src_port <= s_axil_wdata[31:16];
              rule_table_storage[s_axil_awaddr[6:4]].dst_port <= s_axil_wdata[15:0];
            end
            2'd3: begin
              rule_table_storage[s_axil_awaddr[6:4]].src_prefix_len <= s_axil_wdata[31:24];
              rule_table_storage[s_axil_awaddr[6:4]].dst_prefix_len <= s_axil_wdata[23:16];
              rule_table_storage[s_axil_awaddr[6:4]].protocol       <= s_axil_wdata[15:8];
              rule_table_storage[s_axil_awaddr[6:4]].action         <= s_axil_wdata[7:5];
              rule_table_storage[s_axil_awaddr[6:4]].reserved       <= s_axil_wdata[4:1];
              rule_table_storage[s_axil_awaddr[6:4]].enable         <= s_axil_wdata[0];
            end
          endcase
        end

        s_axil_awready <= 1'b0;
        s_axil_wready  <= 1'b0;
        s_axil_bvalid  <= 1'b1;
        s_axil_bresp   <= 2'b00;
      end

      if (s_axil_bvalid && s_axil_bready) begin
        s_axil_bvalid  <= 1'b0;
        s_axil_awready <= 1'b1;
        s_axil_wready  <= 1'b1;
      end
    end
  end


  // ---------------------------------------------------------------------------
  // TUSER attach + passthrough
  //
  // tdata/tvalid/tlast pass through combinationally. tuser_reg holds the
  // most recent verdict's summary bits (drop, any_hit, any_anomaly, rsvd)
  // and is updated on each verdict_valid. The phase relationship is
  // one-packet-delayed: verdict is computed after the bytes flow by, so
  // tuser reflects the previous packet during the current packet's bytes.
  // Downstream consumers must account for this.
  // ---------------------------------------------------------------------------
  logic [3:0] tuser_reg;

  always_ff @(posedge aclk) begin
    if (!aresetn)
      tuser_reg <= 4'd0;
    else if (verdict_valid)
      tuser_reg <= {1'b0, |verdict.anomaly_bits, verdict.any_hit, verdict.drop};
  end

  assign m_axis_tdata  = s_axis_tdata;
  assign m_axis_tvalid = s_axis_tvalid;
  assign m_axis_tlast  = s_axis_tlast;
  assign m_axis_tuser  = tuser_reg;

endmodule