// ============================================================================
// FormalGuard — AES-256 Timing Properties (Side-Channel Resistance)
// ============================================================================
// Property IDs: FG_AES_TIME_001 through FG_AES_TIME_003
// Compliance:   PCI-DSS 3.5.1, FIPS 140-3
//
// These properties verify that AES-256 implementations execute in constant
// time regardless of key or plaintext values, preventing timing side-channel
// attacks that could leak secret key material.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module fg_aes_timing (
  fg_aes256_if.props aes
);

  import fg_pkg::*;

  // ==========================================================================
  // Internal Cycle Counting
  // ==========================================================================
  // Track the number of clock cycles each operation takes. The formal tool
  // explores all possible input values; any input that causes a different
  // cycle count produces a counterexample.

  logic [15:0] op_cycle_count;    // Cycles for current operation
  logic [15:0] last_op_cycles;    // Cycles taken by the previous operation
  logic        last_op_valid;     // We have a valid previous measurement
  logic        counting;          // Currently timing an operation

  // Track key and plaintext of previous and current operations
  logic [255:0] prev_key;
  logic [255:0] curr_key;
  logic [127:0] prev_plaintext;
  logic [127:0] curr_plaintext;

  always_ff @(posedge aes.clk or negedge aes.rst_n) begin
    if (!aes.rst_n) begin
      op_cycle_count <= '0;
      last_op_cycles <= '0;
      last_op_valid  <= 1'b0;
      counting       <= 1'b0;
      prev_key       <= '0;
      curr_key       <= '0;
      prev_plaintext <= '0;
      curr_plaintext <= '0;
    end else begin
      if (aes.start && aes.key_valid && !aes.busy) begin
        // New operation starting — begin counting
        op_cycle_count <= 16'd1;
        counting       <= 1'b1;
        curr_key       <= aes.key;
        curr_plaintext <= aes.plaintext;
      end else if (counting && !aes.done) begin
        op_cycle_count <= op_cycle_count + 16'd1;
      end

      if (aes.done && counting) begin
        // Operation complete — store measurement
        last_op_cycles <= op_cycle_count;
        last_op_valid  <= 1'b1;
        counting       <= 1'b0;
        prev_key       <= curr_key;
        prev_plaintext <= curr_plaintext;
      end
    end
  end

  // ==========================================================================
  // FG_AES_TIME_001 — Key-Independent Constant Time
  // ==========================================================================
  // Encryption latency must be identical regardless of key value.
  // If two operations with different keys take different cycle counts,
  // the implementation has a key-dependent timing side-channel.
  //
  // Compliance: PCI-DSS 3.5.1, FIPS 140-3
  // ==========================================================================

  property p_aes_time_001;
    @(posedge aes.clk) disable iff (!aes.rst_n)
    (aes.done && counting && last_op_valid && !aes.error &&
     curr_key != prev_key)
    |-> (op_cycle_count == last_op_cycles);
  endproperty

  FG_AES_TIME_001: assert property (p_aes_time_001)
    else $error("FG_AES_TIME_001 FAIL: Key-dependent timing detected — %0d vs %0d cycles",
                op_cycle_count, last_op_cycles);

  // ==========================================================================
  // FG_AES_TIME_002 — Plaintext-Independent Constant Time
  // ==========================================================================
  // Encryption latency must be identical regardless of plaintext value.
  //
  // Compliance: PCI-DSS 3.5.1
  // ==========================================================================

  property p_aes_time_002;
    @(posedge aes.clk) disable iff (!aes.rst_n)
    (aes.done && counting && last_op_valid && !aes.error &&
     curr_plaintext != prev_plaintext)
    |-> (op_cycle_count == last_op_cycles);
  endproperty

  FG_AES_TIME_002: assert property (p_aes_time_002)
    else $error("FG_AES_TIME_002 FAIL: Plaintext-dependent timing detected — %0d vs %0d cycles",
                op_cycle_count, last_op_cycles);

  // ==========================================================================
  // FG_AES_TIME_003 — No Early Termination
  // ==========================================================================
  // The done signal must not assert before FG_AES_MIN_LATENCY cycles after
  // start. This catches implementations that short-circuit on special inputs
  // (e.g., all-zero key, all-zero plaintext).
  //
  // Compliance: FIPS 140-3
  // ==========================================================================

  logic [15:0] cycles_since_start;

  always_ff @(posedge aes.clk or negedge aes.rst_n) begin
    if (!aes.rst_n) begin
      cycles_since_start <= '0;
    end else begin
      if (aes.start && aes.key_valid && !aes.busy)
        cycles_since_start <= 16'd1;
      else if (cycles_since_start > 0 && !aes.done)
        cycles_since_start <= cycles_since_start + 16'd1;
      else if (aes.done)
        cycles_since_start <= '0;
    end
  end

  property p_aes_time_003;
    @(posedge aes.clk) disable iff (!aes.rst_n)
    (aes.done && !aes.error)
    |-> (cycles_since_start >= FG_AES_MIN_LATENCY);
  endproperty

  FG_AES_TIME_003: assert property (p_aes_time_003)
    else $error("FG_AES_TIME_003 FAIL: Operation completed in %0d cycles (minimum: %0d) — early termination detected",
                cycles_since_start, FG_AES_MIN_LATENCY);

  // ==========================================================================
  // Coverage Points
  // ==========================================================================

  cover property (@(posedge aes.clk) aes.done && counting && last_op_valid);
  cover property (@(posedge aes.clk) aes.done && cycles_since_start == FG_AES_MIN_LATENCY);

endmodule : fg_aes_timing
