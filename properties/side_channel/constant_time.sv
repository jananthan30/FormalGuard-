// ============================================================================
// FormalGuard — Constant-Time Execution Properties
// ============================================================================
// Property IDs: FG_SC_CT_001, FG_SC_CT_002
// Compliance:   PCI-DSS 3.5.1, FIPS 140-3
//
// Verifies that cryptographic operations execute in constant time
// and have no conditional branches dependent on secret data.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module fg_sc_constant_time (
  fg_sc_if.props sc
);

  import fg_pkg::*;

  // ==========================================================================
  // FG_SC_CT_001 — Secret-Independent Execution Path Length
  // ==========================================================================
  // The number of clock cycles from op_start to op_done must be identical
  // regardless of the secret_data value. The formal tool explores all
  // possible secret values; any two secrets causing different cycle counts
  // produce a counterexample.
  //
  // Compliance: PCI-DSS 3.5.1, FIPS 140-3
  // ==========================================================================

  logic [31:0] op_cycles;
  logic [31:0] last_cycles;
  logic        last_valid;
  logic        timing;
  logic [255:0] prev_secret;
  logic [255:0] curr_secret;

  always_ff @(posedge sc.clk or negedge sc.rst_n) begin
    if (!sc.rst_n) begin
      op_cycles   <= '0;
      last_cycles <= '0;
      last_valid  <= 1'b0;
      timing      <= 1'b0;
      prev_secret <= '0;
      curr_secret <= '0;
    end else begin
      if (sc.op_start && !sc.op_busy) begin
        op_cycles   <= 32'd1;
        timing      <= 1'b1;
        curr_secret <= sc.secret_data;
      end else if (timing && !sc.op_done) begin
        op_cycles <= op_cycles + 32'd1;
      end

      if (sc.op_done && timing) begin
        last_cycles <= op_cycles;
        last_valid  <= 1'b1;
        timing      <= 1'b0;
        prev_secret <= curr_secret;
      end
    end
  end

  property p_sc_ct_001;
    @(posedge sc.clk) disable iff (!sc.rst_n)
    (sc.op_done && timing && last_valid &&
     curr_secret != prev_secret)
    |-> (op_cycles == last_cycles);
  endproperty

  FG_SC_CT_001: assert property (p_sc_ct_001)
    else $error("FG_SC_CT_001 FAIL: Secret-dependent timing — %0d vs %0d cycles",
                op_cycles, last_cycles);

  // ==========================================================================
  // FG_SC_CT_002 — No Secret-Dependent Conditional Branches
  // ==========================================================================
  // The data_dependent_branch signal must never be asserted. This signal
  // is tied high by the design whenever a conditional branch (if/case)
  // uses secret_data as the condition. The formal tool proves this
  // signal is always low.
  //
  // Compliance: FIPS 140-3
  // ==========================================================================

  property p_sc_ct_002;
    @(posedge sc.clk) disable iff (!sc.rst_n)
    !sc.data_dependent_branch;
  endproperty

  FG_SC_CT_002: assert property (p_sc_ct_002)
    else $error("FG_SC_CT_002 FAIL: Conditional branch dependent on secret data detected");

  // Branch trace must be identical regardless of secret
  logic [15:0] prev_branch_trace;
  logic        branch_trace_valid;

  always_ff @(posedge sc.clk or negedge sc.rst_n) begin
    if (!sc.rst_n) begin
      prev_branch_trace  <= '0;
      branch_trace_valid <= 1'b0;
    end else if (sc.op_done) begin
      prev_branch_trace  <= sc.branch_trace;
      branch_trace_valid <= 1'b1;
    end
  end

  property p_sc_ct_002_trace;
    @(posedge sc.clk) disable iff (!sc.rst_n)
    (sc.op_done && branch_trace_valid && curr_secret != prev_secret)
    |-> (sc.branch_trace == prev_branch_trace);
  endproperty

  FG_SC_CT_002_TRC: assert property (p_sc_ct_002_trace)
    else $error("FG_SC_CT_002 FAIL: Branch trace differs between secret values — control flow leak");

  // ==========================================================================
  // Coverage
  // ==========================================================================

  cover property (@(posedge sc.clk) sc.op_done && timing && last_valid);
  cover property (@(posedge sc.clk) sc.op_done && branch_trace_valid);

endmodule : fg_sc_constant_time
