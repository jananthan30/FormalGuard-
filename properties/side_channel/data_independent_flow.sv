// ============================================================================
// FormalGuard — Data-Independent Control Flow Properties
// ============================================================================
// Property ID:  FG_SC_DIF_001
// Compliance:   FIPS 140-3
//
// Verifies that the control flow graph is identical for all possible
// secret inputs. The FSM state trace / program counter trace must not
// vary based on secret data values.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module fg_sc_data_independent_flow (
  fg_sc_if.props sc
);

  import fg_pkg::*;

  // ==========================================================================
  // FG_SC_DIF_001 — Identical Control Flow for All Secrets
  // ==========================================================================
  // The pc_trace (FSM state sequence) must be identical regardless of
  // the secret_data input. If different secrets cause the FSM to visit
  // different states, the implementation has a data-dependent control
  // flow that leaks information through timing, power, or EM side-channels.
  //
  // Compliance: FIPS 140-3
  // ==========================================================================

  // Accumulate a hash of the PC trace during operation
  logic [31:0] trace_hash;
  logic [31:0] prev_trace_hash;
  logic        trace_valid;
  logic        accumulating;
  logic [255:0] prev_secret;
  logic [255:0] curr_secret;

  // Simple rolling hash of the PC trace
  always_ff @(posedge sc.clk or negedge sc.rst_n) begin
    if (!sc.rst_n) begin
      trace_hash      <= '0;
      prev_trace_hash <= '0;
      trace_valid     <= 1'b0;
      accumulating    <= 1'b0;
      prev_secret     <= '0;
      curr_secret     <= '0;
    end else begin
      if (sc.op_start && !sc.op_busy) begin
        trace_hash   <= 32'h811c9dc5;  // FNV-1a offset basis
        accumulating <= 1'b1;
        curr_secret  <= sc.secret_data;
      end

      if (accumulating && sc.op_busy) begin
        // FNV-1a-like hash of PC trace
        trace_hash <= (trace_hash ^ {24'h0, sc.pc_trace}) * 32'h01000193;
      end

      if (sc.op_done && accumulating) begin
        prev_trace_hash <= trace_hash;
        trace_valid     <= 1'b1;
        accumulating    <= 1'b0;
        prev_secret     <= curr_secret;
      end
    end
  end

  property p_sc_dif_001;
    @(posedge sc.clk) disable iff (!sc.rst_n)
    (sc.op_done && accumulating && trace_valid &&
     curr_secret != prev_secret)
    |-> (trace_hash == prev_trace_hash);
  endproperty

  FG_SC_DIF_001: assert property (p_sc_dif_001)
    else $error("FG_SC_DIF_001 FAIL: Control flow differs for different secrets — data-dependent flow detected");

  // The total number of branches must also be identical
  logic [15:0] prev_branch_count;
  logic        branch_count_valid;

  always_ff @(posedge sc.clk or negedge sc.rst_n) begin
    if (!sc.rst_n) begin
      prev_branch_count  <= '0;
      branch_count_valid <= 1'b0;
    end else if (sc.op_done) begin
      prev_branch_count  <= sc.branch_count;
      branch_count_valid <= 1'b1;
    end
  end

  property p_sc_dif_001_branch_count;
    @(posedge sc.clk) disable iff (!sc.rst_n)
    (sc.op_done && branch_count_valid && curr_secret != prev_secret)
    |-> (sc.branch_count == prev_branch_count);
  endproperty

  FG_SC_DIF_001_BC: assert property (p_sc_dif_001_branch_count)
    else $error("FG_SC_DIF_001 FAIL: Branch count differs — %0d vs %0d",
                sc.branch_count, prev_branch_count);

  // ==========================================================================
  // Coverage
  // ==========================================================================

  cover property (@(posedge sc.clk) sc.op_done && accumulating && trace_valid);

endmodule : fg_sc_data_independent_flow
