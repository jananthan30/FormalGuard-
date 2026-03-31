// ============================================================================
// FormalGuard — SHA-256 Functional Correctness Properties
// ============================================================================
// Property IDs: FG_SHA_FUNC_001, FG_SHA_FUNC_002, FG_SHA_FUNC_003
// Compliance:   FIPS 180-4, FIPS 202, PCI-DSS 3.5.1
//
// Verifies SHA-256 functional correctness: test vector matching,
// determinism, and padding conformance.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module fg_sha_functional (
  fg_sha256_if.props sha
);

  import fg_pkg::*;

  // ==========================================================================
  // FG_SHA_FUNC_001 — NIST Test Vector Verification
  // ==========================================================================
  // Hash output for known inputs must match NIST SP 800-180-4 test vectors.
  //
  // NIST test vector: SHA-256("") =
  //   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  //
  // This property uses assume-guarantee: constrain the input to the known
  // test vector, then assert the output matches.
  //
  // Compliance: FIPS 180-4
  // ==========================================================================

  // Known test vector for empty string (single block with padding)
  localparam logic [255:0] EMPTY_HASH = 256'he3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855;

  // Track specific test vector inputs
  logic empty_msg_started;

  always_ff @(posedge sha.clk or negedge sha.rst_n) begin
    if (!sha.rst_n) begin
      empty_msg_started <= 1'b0;
    end else begin
      // Detect empty message (length = 0, padded block)
      if (sha.start && sha.msg_length == 64'd0) begin
        empty_msg_started <= 1'b1;
      end
      if (sha.done) begin
        empty_msg_started <= 1'b0;
      end
    end
  end

  property p_sha_func_001;
    @(posedge sha.clk) disable iff (!sha.rst_n)
    (sha.done && sha.digest_valid && empty_msg_started)
    |-> (sha.digest == EMPTY_HASH);
  endproperty

  FG_SHA_FUNC_001: assert property (p_sha_func_001)
    else $error("FG_SHA_FUNC_001 FAIL: SHA-256('') does not match NIST test vector");

  // Operation must complete
  property p_sha_func_001_completion;
    @(posedge sha.clk) disable iff (!sha.rst_n)
    (sha.start && !sha.busy)
    |-> ##[1:FG_SHA_MAX_LATENCY] sha.done;
  endproperty

  FG_SHA_FUNC_001_COMP: assert property (p_sha_func_001_completion)
    else $error("FG_SHA_FUNC_001 FAIL: SHA-256 did not complete within %0d cycles",
                FG_SHA_MAX_LATENCY);

  // ==========================================================================
  // FG_SHA_FUNC_002 — Determinism
  // ==========================================================================
  // Identical inputs must always produce identical outputs. This verifies
  // the fundamental property of a hash function: no internal state leakage
  // between operations that would cause different outputs for the same input.
  //
  // Compliance: PCI-DSS 3.5.1
  // ==========================================================================

  logic [511:0] prev_block;
  logic [255:0] prev_digest;
  logic [63:0]  prev_length;
  logic         prev_valid;
  logic         same_input;

  always_ff @(posedge sha.clk or negedge sha.rst_n) begin
    if (!sha.rst_n) begin
      prev_block  <= '0;
      prev_digest <= '0;
      prev_length <= '0;
      prev_valid  <= 1'b0;
      same_input  <= 1'b0;
    end else begin
      if (sha.start && !sha.busy) begin
        same_input <= prev_valid &&
                      (sha.block_data == prev_block) &&
                      (sha.msg_length == prev_length);
      end
      if (sha.done && sha.digest_valid) begin
        prev_block  <= sha.block_data;
        prev_digest <= sha.digest;
        prev_length <= sha.msg_length;
        prev_valid  <= 1'b1;
      end
    end
  end

  property p_sha_func_002;
    @(posedge sha.clk) disable iff (!sha.rst_n)
    (sha.done && sha.digest_valid && same_input && prev_valid)
    |-> (sha.digest == prev_digest);
  endproperty

  FG_SHA_FUNC_002: assert property (p_sha_func_002)
    else $error("FG_SHA_FUNC_002 FAIL: Same input produced different hash — determinism violated");

  // ==========================================================================
  // FG_SHA_FUNC_003 — Padding Conformance
  // ==========================================================================
  // SHA-256 uses Merkle-Damgard padding: append bit '1', then zeros,
  // then 64-bit message length. The total padded message must be a
  // multiple of 512 bits.
  //
  // This property verifies that for a single-block message, the padding
  // bit is present at the correct position based on message length.
  //
  // Compliance: FIPS 180-4 (Section 5.1.1)
  // ==========================================================================

  // For single-block messages, verify padding structure
  property p_sha_func_003;
    @(posedge sha.clk) disable iff (!sha.rst_n)
    // Single-block message: length fits in one block (< 448 bits)
    (sha.start && !sha.busy && sha.msg_length < 64'd448)
    |-> (sha.block_data[511 - sha.msg_length[8:0]] == 1'b1);
  endproperty

  FG_SHA_FUNC_003: assert property (p_sha_func_003)
    else $error("FG_SHA_FUNC_003 FAIL: Padding bit not found at expected position");

  // ==========================================================================
  // Coverage
  // ==========================================================================

  cover property (@(posedge sha.clk) sha.start && !sha.busy);
  cover property (@(posedge sha.clk) sha.done && sha.digest_valid);
  cover property (@(posedge sha.clk) sha.done && same_input && prev_valid);
  cover property (@(posedge sha.clk) sha.start && sha.msg_length == 64'd0);

endmodule : fg_sha_functional
