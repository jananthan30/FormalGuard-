// ============================================================================
// FormalGuard — HSM Tamper Detection Properties
// ============================================================================
// Property ID:  FG_HSM_TAMP_001
// Compliance:   FIPS 140-3 Level 3+
//
// Verifies that physical tamper detection triggers immediate zeroization
// within a bounded number of clock cycles.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module fg_hsm_tamper_detect (
  fg_hsm_if.props hsm
);

  import fg_pkg::*;

  // ==========================================================================
  // FG_HSM_TAMP_001 — Tamper Triggers Bounded Zeroization
  // ==========================================================================
  // When the tamper_detect signal is asserted (from physical tamper sensors),
  // the HSM must initiate zeroization and complete it within a bounded
  // number of cycles. The response must be fast enough to prevent key
  // extraction during the tamper event.
  //
  // Compliance: FIPS 140-3 Level 3+
  // ==========================================================================

  // Tamper must trigger zeroization start within 2 cycles
  property p_hsm_tamp_001_start;
    @(posedge hsm.clk) disable iff (!hsm.rst_n)
    ($rose(hsm.tamper_detect))
    |-> ##[0:2] hsm.zeroize_active;
  endproperty

  FG_HSM_TAMP_001_START: assert property (p_hsm_tamp_001_start)
    else $error("FG_HSM_TAMP_001 FAIL: Tamper detected but zeroization not initiated within 2 cycles");

  // Zeroization must complete within bounded time after tamper
  property p_hsm_tamp_001;
    @(posedge hsm.clk) disable iff (!hsm.rst_n)
    ($rose(hsm.tamper_detect))
    |-> ##[1:FG_HSM_ZEROIZE_MAX] hsm.zeroize_done;
  endproperty

  FG_HSM_TAMP_001: assert property (p_hsm_tamp_001)
    else $error("FG_HSM_TAMP_001 FAIL: Zeroization not complete within %0d cycles of tamper",
                FG_HSM_ZEROIZE_MAX);

  // HSM must enter TAMPERED state after tamper detection
  property p_hsm_tamp_001_state;
    @(posedge hsm.clk) disable iff (!hsm.rst_n)
    ($rose(hsm.tamper_detect))
    |-> ##[0:FG_HSM_ZEROIZE_MAX] (hsm.state == HSM_TAMPERED);
  endproperty

  FG_HSM_TAMP_001_STATE: assert property (p_hsm_tamp_001_state)
    else $error("FG_HSM_TAMP_001 FAIL: HSM did not enter TAMPERED state after tamper detection");

  // ==========================================================================
  // Coverage
  // ==========================================================================

  cover property (@(posedge hsm.clk) $rose(hsm.tamper_detect));
  cover property (@(posedge hsm.clk) hsm.zeroize_active && hsm.tamper_detect);
  cover property (@(posedge hsm.clk) hsm.zeroize_done && hsm.state == HSM_TAMPERED);

endmodule : fg_hsm_tamper_detect
