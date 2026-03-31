// ============================================================================
// FormalGuard — HSM Key Rotation Properties
// ============================================================================
// Property ID:  FG_HSM_KEY_004
// Compliance:   PCI-DSS 3.6.4
//
// Verifies that key rotation is atomic: the old key becomes invalid only
// after the new key is confirmed active. This prevents a window where
// neither key is usable (service disruption) or both are valid
// (security weakness).
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module fg_hsm_key_rotation (
  fg_hsm_if.props hsm
);

  import fg_pkg::*;

  // ==========================================================================
  // FG_HSM_KEY_004 — Atomic Key Rotation
  // ==========================================================================
  // During key rotation:
  // 1. The new key must be activated BEFORE the old key is invalidated
  // 2. There must be no gap where neither key is valid
  // 3. Rotation must complete (not hang indefinitely)
  //
  // Compliance: PCI-DSS 3.6.4
  // ==========================================================================

  // Track rotation state
  logic rotation_active;

  always_ff @(posedge hsm.clk or negedge hsm.rst_n) begin
    if (!hsm.rst_n) begin
      rotation_active <= 1'b0;
    end else begin
      if (hsm.key_rotate_req && !rotation_active)
        rotation_active <= 1'b1;
      if (hsm.key_rotate_done)
        rotation_active <= 1'b0;
    end
  end

  // New key must be active before old key becomes invalid
  property p_hsm_key_004_order;
    @(posedge hsm.clk) disable iff (!hsm.rst_n)
    (rotation_active && hsm.old_key_invalid)
    |-> hsm.new_key_active;
  endproperty

  FG_HSM_KEY_004: assert property (p_hsm_key_004_order)
    else $error("FG_HSM_KEY_004 FAIL: Old key invalidated before new key activated — non-atomic rotation");

  // Rotation must complete within a bounded time
  property p_hsm_key_004_completion;
    @(posedge hsm.clk) disable iff (!hsm.rst_n)
    (hsm.key_rotate_req && !rotation_active)
    |-> ##[1:FG_HSM_ZEROIZE_MAX * 2] hsm.key_rotate_done;
  endproperty

  FG_HSM_KEY_004_COMP: assert property (p_hsm_key_004_completion)
    else $error("FG_HSM_KEY_004 FAIL: Key rotation did not complete within bounded time");

  // ==========================================================================
  // Coverage
  // ==========================================================================

  cover property (@(posedge hsm.clk) hsm.key_rotate_req && !rotation_active);
  cover property (@(posedge hsm.clk) hsm.key_rotate_done);
  cover property (@(posedge hsm.clk) hsm.new_key_active && !hsm.old_key_invalid);

endmodule : fg_hsm_key_rotation
