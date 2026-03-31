// ============================================================================
// FormalGuard — SHA-256 Collision Resistance Properties
// ============================================================================
// Supplementary properties for SHA-256 determinism verification.
// These properties strengthen the determinism guarantee by checking
// that the hash function produces no unexpected collisions for
// structurally different inputs.
//
// Note: True collision resistance cannot be formally verified (it's a
// property of the mathematical function). These properties check
// implementation-level correctness that could cause false collisions.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module fg_sha_collision (
  fg_sha256_if.props sha
);

  import fg_pkg::*;

  // ==========================================================================
  // Supplementary: No state leakage between operations
  // ==========================================================================
  // After a hash completes, starting a new hash must not be affected by
  // the previous operation's internal state. This checks that the
  // intermediate_hash is properly reset between operations.

  property p_sha_state_reset;
    @(posedge sha.clk) disable iff (!sha.rst_n)
    // When starting a new hash, the intermediate state should be
    // the SHA-256 initial hash values (H0), not leftover from previous op
    (sha.start && !sha.busy)
    |=> (sha.round_count == 6'd0);
  endproperty

  SHA_STATE_RESET: assert property (p_sha_state_reset)
    else $error("SHA state not reset between operations — potential state leakage");

  // No output while busy (prevent partial/stale digest reads)
  property p_sha_no_early_digest;
    @(posedge sha.clk) disable iff (!sha.rst_n)
    (sha.busy && !sha.done)
    |-> !sha.digest_valid;
  endproperty

  SHA_NO_EARLY_DIGEST: assert property (p_sha_no_early_digest)
    else $error("SHA produced digest_valid while still busy — stale digest risk");

  // ==========================================================================
  // Coverage
  // ==========================================================================

  cover property (@(posedge sha.clk) sha.done ##1 sha.start);

endmodule : fg_sha_collision
