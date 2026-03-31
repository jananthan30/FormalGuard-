// ============================================================================
// FormalGuard — SHA-256 Binding Interface
// ============================================================================
// Standardized interface for binding FormalGuard SHA-256 verification
// properties to any SHA-256 implementation.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

interface fg_sha256_if;

  import fg_pkg::*;

  // Clock and Reset
  logic         clk;
  logic         rst_n;

  // Control
  logic         start;          // Begin hashing a new message
  logic         update;         // Process next block of multi-block message
  logic         done;           // Hash computation complete
  logic         busy;
  logic         error;

  // Data
  logic [511:0] block_data;     // 512-bit input block
  logic [255:0] digest;         // 256-bit hash output
  logic         digest_valid;   // Digest is ready
  logic [63:0]  msg_length;     // Total message length in bits

  // Observation
  logic [255:0] intermediate_hash; // H values after current block
  logic [5:0]   round_count;       // Current compression round (0-63)

  // Clocking Block
  clocking cb @(posedge clk);
    input rst_n;
    input start, update, done, busy, error;
    input block_data, digest, digest_valid, msg_length;
    input intermediate_hash, round_count;
  endclocking

  modport props (
    input  clk, rst_n,
    input  start, update, done, busy, error,
    input  block_data, digest, digest_valid, msg_length,
    input  intermediate_hash, round_count,
    clocking cb
  );

  modport dut (
    input  clk, rst_n,
    input  start, update,
    input  block_data, msg_length,
    output done, busy, error,
    output digest, digest_valid,
    output intermediate_hash, round_count
  );

endinterface : fg_sha256_if
