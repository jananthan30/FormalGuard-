// ============================================================================
// FormalGuard — AES-256 Binding Interface
// ============================================================================
// Standardized interface for binding FormalGuard AES-256 verification
// properties to any AES-256 implementation. Users write a thin binding
// module to connect their design signals to this interface.
//
// See SPEC.md Section 2.2 for the binding model description.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

interface fg_aes256_if;

  import fg_pkg::*;

  // ---- Clock and Reset ----
  logic         clk;
  logic         rst_n;

  // ---- Control Signals ----
  logic         start;          // Pulse to begin encrypt/decrypt
  logic         done;           // Asserted when operation completes
  logic         busy;           // High while operation is in progress
  logic         encrypt;        // 1 = encrypt, 0 = decrypt
  logic         error;          // Asserted on any detected error condition

  // ---- Data Signals ----
  logic [255:0] key;            // Cipher key
  logic [127:0] plaintext;      // Input data (plaintext for encrypt, ciphertext for decrypt)
  logic [127:0] ciphertext;     // Output data
  logic         key_valid;      // Key has been loaded and is valid
  logic [8:0]   key_length;     // Actual key length in bits (must be >= 256)

  // ---- Optional Observation Signals ----
  // These enable deeper properties (fault detection, round-key verification).
  // Designs that don't expose internals can tie these to 0.
  logic [127:0] round_key;      // Current round key
  logic [3:0]   round_count;    // Current round number (0-13 for AES-256)
  logic [127:0] state_reg;      // Internal state register (for fault injection checks)
  logic         internal_err;   // Internal consistency check flag

  // ---- Clocking Block ----
  // All properties sample signals through this clocking block to ensure
  // consistent sampling at the positive clock edge and avoid race conditions.
  clocking cb @(posedge clk);
    input rst_n;
    input start, done, busy, encrypt, error;
    input key, plaintext, ciphertext, key_valid, key_length;
    input round_key, round_count, state_reg, internal_err;
  endclocking

  // ---- Modports ----

  // Property-side view: all signals are inputs (observed, not driven)
  modport props (
    input  clk, rst_n,
    input  start, done, busy, encrypt, error,
    input  key, plaintext, ciphertext, key_valid, key_length,
    input  round_key, round_count, state_reg, internal_err,
    clocking cb
  );

  // Design-side view: proper I/O directionality
  modport dut (
    input  clk, rst_n,
    input  start, encrypt,
    input  key, plaintext, key_valid, key_length,
    output done, busy, error,
    output ciphertext,
    output round_key, round_count, state_reg, internal_err
  );

endinterface : fg_aes256_if
