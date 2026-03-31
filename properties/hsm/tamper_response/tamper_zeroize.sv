// ============================================================================
// FormalGuard — HSM Tamper Zeroization Properties
// ============================================================================
// Property IDs: FG_HSM_TAMP_002, FG_HSM_TAMP_003
// Compliance:   FIPS 140-3
//
// Verifies that once zeroization begins it cannot be interrupted, and
// that the post-tamper state contains no recoverable key material.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module fg_hsm_tamper_zeroize (
  fg_hsm_if.props hsm
);

  import fg_pkg::*;

  // ==========================================================================
  // FG_HSM_TAMP_002 — Non-Interruptible Zeroization
  // ==========================================================================
  // Once zeroization begins (zeroize_active asserted), it must not be
  // interrupted or cancelled. The zeroize_active signal must remain high
  // until zeroize_done is asserted. No other operations should be able
  // to stop the zeroization process.
  //
  // Compliance: FIPS 140-3
  // ==========================================================================

  property p_hsm_tamp_002;
    @(posedge hsm.clk) disable iff (!hsm.rst_n)
    // Once zeroize_active is high, it stays high until done
    (hsm.zeroize_active && !hsm.zeroize_done)
    |=> hsm.zeroize_active;
  endproperty

  FG_HSM_TAMP_002: assert property (p_hsm_tamp_002)
    else $error("FG_HSM_TAMP_002 FAIL: Zeroization interrupted before completion");

  // During zeroization, no new operations should be accepted
  property p_hsm_tamp_002_no_ops;
    @(posedge hsm.clk) disable iff (!hsm.rst_n)
    (hsm.zeroize_active)
    |-> (!hsm.crypto_op_done && !hsm.auth_granted && !hsm.key_gen_done);
  endproperty

  FG_HSM_TAMP_002_NOOPS: assert property (p_hsm_tamp_002_no_ops)
    else $error("FG_HSM_TAMP_002 FAIL: Operations completed during active zeroization");

  // ==========================================================================
  // FG_HSM_TAMP_003 — No Key Remnants Post-Tamper
  // ==========================================================================
  // After tamper-triggered zeroization completes, ALL key slots must be
  // zeroed (not just the one being used). The HSM state must be
  // non-recoverable — no key material should remain anywhere.
  //
  // Compliance: FIPS 140-3
  // ==========================================================================

  // Check ALL key slots are zeroed after tamper zeroization
  genvar slot;
  generate
    for (slot = 0; slot < FG_HSM_KEY_SLOTS; slot++) begin : gen_tamp_zero_check

      property p_hsm_tamp_003_slot;
        @(posedge hsm.clk) disable iff (!hsm.rst_n)
        (hsm.zeroize_done && hsm.state == HSM_TAMPERED)
        |-> (hsm.key_store[slot] == '0);
      endproperty

      FG_HSM_TAMP_003_SLOT: assert property (p_hsm_tamp_003_slot)
        else $error("FG_HSM_TAMP_003 FAIL: Key remnants in slot %0d after tamper zeroization", slot);

    end
  endgenerate

  // RAM must also be clean
  property p_hsm_tamp_003_ram;
    @(posedge hsm.clk) disable iff (!hsm.rst_n)
    (hsm.zeroize_done && hsm.state == HSM_TAMPERED)
    |-> (hsm.ram_content == '0);
  endproperty

  FG_HSM_TAMP_003: assert property (p_hsm_tamp_003_ram)
    else $error("FG_HSM_TAMP_003 FAIL: Key remnants in RAM after tamper zeroization");

  // Post-tamper state must be non-recoverable (stays in TAMPERED)
  property p_hsm_tamp_003_permanent;
    @(posedge hsm.clk) disable iff (!hsm.rst_n)
    (hsm.state == HSM_TAMPERED)
    |=> (hsm.state == HSM_TAMPERED);
  endproperty

  FG_HSM_TAMP_003_PERM: assert property (p_hsm_tamp_003_permanent)
    else $error("FG_HSM_TAMP_003 FAIL: HSM recovered from TAMPERED state — should be permanent");

  // ==========================================================================
  // Coverage
  // ==========================================================================

  cover property (@(posedge hsm.clk) hsm.zeroize_active && !hsm.zeroize_done);
  cover property (@(posedge hsm.clk) hsm.zeroize_done && hsm.state == HSM_TAMPERED);

endmodule : fg_hsm_tamper_zeroize
