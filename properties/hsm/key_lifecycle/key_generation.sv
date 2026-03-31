// ============================================================================
// FormalGuard — HSM Key Generation Properties
// ============================================================================
// Property ID:  FG_HSM_KEY_001
// Compliance:   PCI-DSS 3.6.1, FIPS 140-3
//
// Verifies that generated keys meet minimum entropy and length requirements.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module fg_hsm_key_generation (
  fg_hsm_if.props hsm
);

  import fg_pkg::*;

  // ==========================================================================
  // FG_HSM_KEY_001 — Minimum Entropy / Key Length
  // ==========================================================================
  // Generated keys must meet minimum length requirements. When key generation
  // completes, the key length must be at least 256 bits and the key data
  // must not be all-zeros (trivially weak key).
  //
  // A production entropy check would verify the RNG source; here we check
  // the observable output: key length and non-triviality.
  //
  // Compliance: PCI-DSS 3.6.1
  // ==========================================================================

  // Track key generation cycles
  logic key_gen_active;
  logic [15:0] key_gen_cycles;

  always_ff @(posedge hsm.clk or negedge hsm.rst_n) begin
    if (!hsm.rst_n) begin
      key_gen_active <= 1'b0;
      key_gen_cycles <= '0;
    end else begin
      if (hsm.key_gen_req && !key_gen_active) begin
        key_gen_active <= 1'b1;
        key_gen_cycles <= 16'd1;
      end else if (key_gen_active && !hsm.key_gen_done) begin
        key_gen_cycles <= key_gen_cycles + 16'd1;
      end else if (hsm.key_gen_done) begin
        key_gen_active <= 1'b0;
      end
    end
  end

  // Key length must be >= 256 bits upon generation completion
  property p_hsm_key_001_length;
    @(posedge hsm.clk) disable iff (!hsm.rst_n)
    (hsm.key_gen_done && hsm.key_valid)
    |-> (hsm.key_length >= 9'd256);
  endproperty

  FG_HSM_KEY_001_LEN: assert property (p_hsm_key_001_length)
    else $error("FG_HSM_KEY_001 FAIL: Generated key length %0d < 256 bits", hsm.key_length);

  // Key data must not be trivially weak (all-zeros or all-ones)
  property p_hsm_key_001_nontrivial;
    @(posedge hsm.clk) disable iff (!hsm.rst_n)
    (hsm.key_gen_done && hsm.key_valid)
    |-> (hsm.key_data != '0) && (hsm.key_data != '1);
  endproperty

  FG_HSM_KEY_001: assert property (p_hsm_key_001_nontrivial)
    else $error("FG_HSM_KEY_001 FAIL: Generated key is trivially weak (all-zeros or all-ones)");

  // ==========================================================================
  // Coverage
  // ==========================================================================

  cover property (@(posedge hsm.clk) hsm.key_gen_done && hsm.key_valid);
  cover property (@(posedge hsm.clk) hsm.key_gen_req && !key_gen_active);

endmodule : fg_hsm_key_generation
