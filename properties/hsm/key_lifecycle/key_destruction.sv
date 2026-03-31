// ============================================================================
// FormalGuard — HSM Key Destruction (Zeroization) Properties
// ============================================================================
// Property IDs: FG_HSM_KEY_003, FG_HSM_KEY_005
// Compliance:   FIPS 140-3, PCI-DSS 3.6.5
//
// Verifies complete and timely key destruction. After a zeroize command,
// all copies of the key material must be overwritten, and no remnants
// may persist in RAM.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module fg_hsm_key_destruction (
  fg_hsm_if.props hsm
);

  import fg_pkg::*;

  // ==========================================================================
  // FG_HSM_KEY_003 — Bounded Zeroization Time
  // ==========================================================================
  // Key destruction must complete (all copies overwritten) within a bounded
  // number of clock cycles. An unbounded or excessively slow zeroization
  // leaves a window for key extraction.
  //
  // Compliance: FIPS 140-3, PCI-DSS 3.6.5
  // ==========================================================================

  property p_hsm_key_003;
    @(posedge hsm.clk) disable iff (!hsm.rst_n)
    (hsm.key_destroy_req)
    |-> ##[1:FG_HSM_ZEROIZE_MAX] hsm.key_destroy_done;
  endproperty

  FG_HSM_KEY_003: assert property (p_hsm_key_003)
    else $error("FG_HSM_KEY_003 FAIL: Key destruction did not complete within %0d cycles",
                FG_HSM_ZEROIZE_MAX);

  // ==========================================================================
  // FG_HSM_KEY_005 — No Key Remnants After Zeroization
  // ==========================================================================
  // After the zeroize_done signal is asserted, no key material may persist
  // in RAM or the key store for the targeted slot. This checks both the
  // key_store array and the ram_content observation signal.
  //
  // This catches HSMs that report "done" but leave partial key material
  // in storage (e.g., only clearing the first word but not the rest).
  //
  // Compliance: FIPS 140-3
  // ==========================================================================

  // Capture which key slot is being destroyed
  logic [3:0] destroy_target_id;
  logic       destroy_in_progress;

  always_ff @(posedge hsm.clk or negedge hsm.rst_n) begin
    if (!hsm.rst_n) begin
      destroy_target_id  <= '0;
      destroy_in_progress <= 1'b0;
    end else begin
      if (hsm.key_destroy_req && !destroy_in_progress) begin
        destroy_target_id  <= hsm.key_id;
        destroy_in_progress <= 1'b1;
      end
      if (hsm.key_destroy_done) begin
        destroy_in_progress <= 1'b0;
      end
    end
  end

  // After destruction completes, targeted key slot must be zero
  property p_hsm_key_005_store;
    @(posedge hsm.clk) disable iff (!hsm.rst_n)
    (hsm.key_destroy_done && destroy_in_progress)
    |-> (hsm.key_store[destroy_target_id] == '0);
  endproperty

  FG_HSM_KEY_005: assert property (p_hsm_key_005_store)
    else $error("FG_HSM_KEY_005 FAIL: Key remnants in slot %0d after zeroization complete",
                destroy_target_id);

  // RAM content check: after zeroization, selected RAM must be zero
  property p_hsm_key_005_ram;
    @(posedge hsm.clk) disable iff (!hsm.rst_n)
    (hsm.key_destroy_done && destroy_in_progress)
    |-> (hsm.ram_content == '0);
  endproperty

  FG_HSM_KEY_005_RAM: assert property (p_hsm_key_005_ram)
    else $error("FG_HSM_KEY_005 FAIL: Key remnants in RAM after zeroization complete");

  // ==========================================================================
  // Coverage
  // ==========================================================================

  cover property (@(posedge hsm.clk) hsm.key_destroy_req);
  cover property (@(posedge hsm.clk) hsm.key_destroy_done);
  cover property (@(posedge hsm.clk) hsm.key_destroy_done && hsm.key_store[destroy_target_id] == '0);

endmodule : fg_hsm_key_destruction
