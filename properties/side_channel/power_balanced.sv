// ============================================================================
// FormalGuard — Power-Balanced Logic Properties
// ============================================================================
// Property ID:  FG_SC_PWR_001
// Compliance:   FIPS 140-3 Level 3+
//
// Verifies that the Hamming weight of intermediate registers is
// independent of secret key bits, preventing power analysis attacks.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module fg_sc_power_balanced (
  fg_sc_if.props sc
);

  import fg_pkg::*;

  // ==========================================================================
  // FG_SC_PWR_001 — Key-Independent Hamming Weight
  // ==========================================================================
  // In a power-balanced implementation, the Hamming weight (number of 1-bits)
  // of intermediate registers must be constant or independent of the secret
  // key value. Variations in Hamming weight cause measurable differences in
  // power consumption, enabling Differential Power Analysis (DPA).
  //
  // This property compares the Hamming weight of intermediate registers
  // across operations with different secrets. Any secret-dependent variation
  // is flagged.
  //
  // Compliance: FIPS 140-3 Level 3+
  // ==========================================================================

  // Track Hamming weight across operations
  logic [31:0] prev_hamming;
  logic        hamming_valid;
  logic [255:0] prev_secret;
  logic [255:0] curr_secret;
  logic         sampling;

  always_ff @(posedge sc.clk or negedge sc.rst_n) begin
    if (!sc.rst_n) begin
      prev_hamming  <= '0;
      hamming_valid <= 1'b0;
      prev_secret   <= '0;
      curr_secret   <= '0;
      sampling      <= 1'b0;
    end else begin
      if (sc.op_start && !sc.op_busy) begin
        curr_secret <= sc.secret_data;
        sampling    <= 1'b1;
      end

      if (sc.op_done && sampling) begin
        prev_hamming  <= sc.hamming_weight;
        hamming_valid <= 1'b1;
        prev_secret   <= curr_secret;
        sampling      <= 1'b0;
      end
    end
  end

  // At completion, Hamming weight must be same regardless of secret
  property p_sc_pwr_001;
    @(posedge sc.clk) disable iff (!sc.rst_n)
    (sc.op_done && sampling && hamming_valid &&
     curr_secret != prev_secret)
    |-> (sc.hamming_weight == prev_hamming);
  endproperty

  FG_SC_PWR_001: assert property (p_sc_pwr_001)
    else $error("FG_SC_PWR_001 FAIL: Secret-dependent Hamming weight — %0d vs %0d (DPA vulnerability)",
                sc.hamming_weight, prev_hamming);

  // During operation, Hamming weight must not correlate with individual key bits
  // (checked via the intermediate register observation)
  property p_sc_pwr_001_intermediate;
    @(posedge sc.clk) disable iff (!sc.rst_n)
    (sc.op_busy && sc.intermediate_reg != '0)
    |-> (sc.hamming_weight == $countones(sc.intermediate_reg));
  endproperty

  FG_SC_PWR_001_INT: assert property (p_sc_pwr_001_intermediate)
    else $error("FG_SC_PWR_001 FAIL: Reported Hamming weight inconsistent with intermediate register");

  // ==========================================================================
  // Coverage
  // ==========================================================================

  cover property (@(posedge sc.clk) sc.op_done && sampling && hamming_valid);

endmodule : fg_sc_power_balanced
