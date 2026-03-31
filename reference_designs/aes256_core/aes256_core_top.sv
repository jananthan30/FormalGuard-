// ============================================================================
// AES-256 Core — Top-Level Wrapper for Formal Verification
// ============================================================================
// Wraps aes256_core with proper port declarations for SymbiYosys.
// Includes formal assumptions to constrain the input space.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module aes256_core_top (
  input  logic         clk,
  input  logic         rst_n,
  input  logic         start,
  input  logic         encrypt,
  input  logic [255:0] key,
  input  logic [127:0] plaintext,
  input  logic         key_valid,
  input  logic [8:0]   key_length,
  output logic         done,
  output logic         busy,
  output logic         error,
  output logic [127:0] ciphertext,
  output logic [127:0] round_key,
  output logic [3:0]   round_count,
  output logic [127:0] state_reg,
  output logic         internal_err
);

  // ---- DUT Instance ----
  aes256_core u_dut (
    .clk          (clk),
    .rst_n        (rst_n),
    .start        (start),
    .encrypt      (encrypt),
    .done         (done),
    .busy         (busy),
    .error        (error),
    .key          (key),
    .plaintext    (plaintext),
    .key_valid    (key_valid),
    .key_length   (key_length),
    .ciphertext   (ciphertext),
    .round_key    (round_key),
    .round_count  (round_count),
    .state_reg    (state_reg),
    .internal_err (internal_err)
  );

  // ---- Formal Assumptions ----
  // Constrain inputs to valid stimulus patterns for formal verification.

`ifdef FORMAL
  // Clock and reset assumptions
  initial assume (!rst_n);
  always @(posedge clk) assume (rst_n);  // Release reset after first cycle

  // Don't start a new operation while busy
  always @(posedge clk) begin
    if (busy) assume (!start);
  end

  // Key length is always reported correctly when key_valid
  always @(posedge clk) begin
    if (key_valid) assume (key_length == 9'd256);
  end
`endif

endmodule : aes256_core_top
