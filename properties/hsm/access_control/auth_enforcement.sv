// ============================================================================
// FormalGuard — HSM Access Control Properties
// ============================================================================
// Property IDs: FG_HSM_AUTH_001, FG_HSM_AUTH_002, FG_HSM_AUTH_003
// Compliance:   PCI-DSS 3.5.2, 3.6.6, 8.1.6
//
// Verifies authentication enforcement, dual-control for critical operations,
// and lockout after failed authentication attempts.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module fg_hsm_auth_enforcement (
  fg_hsm_if.props hsm
);

  import fg_pkg::*;

  // ==========================================================================
  // FG_HSM_AUTH_001 — No Crypto Without Authentication
  // ==========================================================================
  // Cryptographic operations must not execute without prior successful
  // authentication. The HSM must be in an authenticated state (READY or
  // BUSY) before any crypto operation can proceed.
  //
  // Compliance: PCI-DSS 3.5.2
  // ==========================================================================

  // Track authentication state
  logic authenticated;

  always_ff @(posedge hsm.clk or negedge hsm.rst_n) begin
    if (!hsm.rst_n) begin
      authenticated <= 1'b0;
    end else begin
      if (hsm.auth_granted)
        authenticated <= 1'b1;
      // Reset auth on tamper, lockout, or explicit deauth
      if (hsm.tamper_detect || hsm.locked ||
          hsm.state == HSM_IDLE || hsm.state == HSM_TAMPERED)
        authenticated <= 1'b0;
    end
  end

  property p_hsm_auth_001;
    @(posedge hsm.clk) disable iff (!hsm.rst_n)
    (hsm.crypto_op_req)
    |-> authenticated;
  endproperty

  FG_HSM_AUTH_001: assert property (p_hsm_auth_001)
    else $error("FG_HSM_AUTH_001 FAIL: Crypto operation requested without prior authentication");

  // Stronger check: crypto operation must not COMPLETE without auth
  property p_hsm_auth_001_complete;
    @(posedge hsm.clk) disable iff (!hsm.rst_n)
    (hsm.crypto_op_done && hsm.crypto_op_valid)
    |-> authenticated;
  endproperty

  FG_HSM_AUTH_001_COMP: assert property (p_hsm_auth_001_complete)
    else $error("FG_HSM_AUTH_001 FAIL: Crypto operation completed without authentication");

  // ==========================================================================
  // FG_HSM_AUTH_002 — Dual Control for Critical Operations
  // ==========================================================================
  // Critical operations (key export, firmware update, key destruction)
  // require two independent authentications from different roles.
  //
  // Compliance: PCI-DSS 3.6.6
  // ==========================================================================

  property p_hsm_auth_002;
    @(posedge hsm.clk) disable iff (!hsm.rst_n)
    // Key destruction is a critical operation requiring dual control
    (hsm.key_destroy_req)
    |-> hsm.dual_control_active;
  endproperty

  FG_HSM_AUTH_002: assert property (p_hsm_auth_002)
    else $error("FG_HSM_AUTH_002 FAIL: Critical operation without dual-control authentication");

  // Dual control requires two separate auth grants
  property p_hsm_auth_002_two_auths;
    @(posedge hsm.clk) disable iff (!hsm.rst_n)
    (hsm.dual_control_active)
    |-> (hsm.auth_granted && hsm.dual_auth_granted);
  endproperty

  FG_HSM_AUTH_002_TWO: assert property (p_hsm_auth_002_two_auths)
    else $error("FG_HSM_AUTH_002 FAIL: Dual control active without two independent authentications");

  // ==========================================================================
  // FG_HSM_AUTH_003 — Lockout After Failed Attempts
  // ==========================================================================
  // After N consecutive failed authentication attempts, the HSM must lock
  // and refuse further authentication attempts until manually reset.
  //
  // Compliance: PCI-DSS 8.1.6
  // ==========================================================================

  property p_hsm_auth_003_increment;
    @(posedge hsm.clk) disable iff (!hsm.rst_n)
    // Fail counter must increment on failed auth
    (hsm.auth_failed && !hsm.locked)
    |=> (hsm.fail_count == $past(hsm.fail_count) + 4'd1);
  endproperty

  FG_HSM_AUTH_003_INC: assert property (p_hsm_auth_003_increment)
    else $error("FG_HSM_AUTH_003 FAIL: Auth failure counter did not increment");

  property p_hsm_auth_003_lockout;
    @(posedge hsm.clk) disable iff (!hsm.rst_n)
    // Must lock when fail count reaches max
    (hsm.fail_count >= FG_HSM_MAX_AUTH_FAIL)
    |-> hsm.locked;
  endproperty

  FG_HSM_AUTH_003: assert property (p_hsm_auth_003_lockout)
    else $error("FG_HSM_AUTH_003 FAIL: HSM not locked after %0d failed auth attempts",
                FG_HSM_MAX_AUTH_FAIL);

  // Locked HSM must not grant authentication
  property p_hsm_auth_003_no_grant;
    @(posedge hsm.clk) disable iff (!hsm.rst_n)
    hsm.locked
    |-> !hsm.auth_granted;
  endproperty

  FG_HSM_AUTH_003_LOCK: assert property (p_hsm_auth_003_no_grant)
    else $error("FG_HSM_AUTH_003 FAIL: Authentication granted while HSM is locked");

  // ==========================================================================
  // Coverage
  // ==========================================================================

  cover property (@(posedge hsm.clk) hsm.auth_granted);
  cover property (@(posedge hsm.clk) hsm.auth_failed);
  cover property (@(posedge hsm.clk) hsm.locked);
  cover property (@(posedge hsm.clk) hsm.dual_control_active);
  cover property (@(posedge hsm.clk) hsm.crypto_op_req && authenticated);

endmodule : fg_hsm_auth_enforcement
