// ============================================================================
// FormalGuard — RSA Binding Interface
// ============================================================================
// Standardized interface for binding FormalGuard RSA verification
// properties to any RSA implementation.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

interface fg_rsa_if;

  import fg_pkg::*;

  // Clock and Reset
  logic         clk;
  logic         rst_n;

  // Control
  logic         start;
  logic         done;
  logic         busy;
  logic         error;
  logic         mode_sign;     // 1 = sign, 0 = verify

  // Data
  logic [2047:0] modulus;       // RSA modulus N
  logic [2047:0] exponent;      // Public or private exponent
  logic [2047:0] message;       // Input message / signature
  logic [2047:0] result_data;   // Output (signature or verification result)
  logic          result_valid;  // Result is valid
  logic [11:0]   key_length;    // Key length in bits

  // Observation
  logic [2047:0] intermediate;  // Intermediate modexp value (for timing checks)
  logic [11:0]   step_count;    // Current step in modular exponentiation

  // Clocking Block
  clocking cb @(posedge clk);
    input rst_n;
    input start, done, busy, error, mode_sign;
    input modulus, exponent, message, result_data, result_valid, key_length;
    input intermediate, step_count;
  endclocking

  modport props (
    input  clk, rst_n,
    input  start, done, busy, error, mode_sign,
    input  modulus, exponent, message, result_data, result_valid, key_length,
    input  intermediate, step_count,
    clocking cb
  );

  modport dut (
    input  clk, rst_n,
    input  start, mode_sign,
    input  modulus, exponent, message, key_length,
    output done, busy, error,
    output result_data, result_valid,
    output intermediate, step_count
  );

endinterface : fg_rsa_if
