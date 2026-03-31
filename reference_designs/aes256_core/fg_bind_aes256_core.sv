// ============================================================================
// FormalGuard — Binding Module for AES-256 Reference Core
// ============================================================================
// Connects the aes256_core reference design to the FormalGuard AES-256
// interface and instantiates all property modules for verification.
//
// This demonstrates the binding pattern that users follow when integrating
// FormalGuard properties with their own AES implementations.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module fg_bind_aes256_core;

  // Instantiate the FormalGuard AES-256 interface
  fg_aes256_if fg_aes();

  // ---- Wire the interface to the DUT ----
  // The DUT (aes256_core) is accessed via hierarchical references.
  // In a bind statement, these resolve to the target instance.

  assign fg_aes.clk          = aes256_core_top.clk;
  assign fg_aes.rst_n        = aes256_core_top.rst_n;
  assign fg_aes.start        = aes256_core_top.start;
  assign fg_aes.done         = aes256_core_top.done;
  assign fg_aes.busy         = aes256_core_top.busy;
  assign fg_aes.encrypt      = aes256_core_top.encrypt;
  assign fg_aes.error        = aes256_core_top.error;
  assign fg_aes.key          = aes256_core_top.key;
  assign fg_aes.plaintext    = aes256_core_top.plaintext;
  assign fg_aes.ciphertext   = aes256_core_top.ciphertext;
  assign fg_aes.key_valid    = aes256_core_top.key_valid;
  assign fg_aes.key_length   = aes256_core_top.key_length;
  assign fg_aes.round_key    = aes256_core_top.round_key;
  assign fg_aes.round_count  = aes256_core_top.round_count;
  assign fg_aes.state_reg    = aes256_core_top.state_reg;
  assign fg_aes.internal_err = aes256_core_top.internal_err;

  // ---- Instantiate FormalGuard property modules ----

  fg_aes_functional u_fg_func (
    .aes (fg_aes.props)
  );

  fg_aes_timing u_fg_timing (
    .aes (fg_aes.props)
  );

  fg_aes_fault u_fg_fault (
    .aes (fg_aes.props)
  );

endmodule : fg_bind_aes256_core
