// ============================================================================
// FormalGuard — RSA Functional Correctness Properties
// ============================================================================
// Property IDs: FG_RSA_FUNC_001, FG_RSA_FUNC_002
// Compliance:   PCI-DSS 3.5.1, 3.6.1
//
// Verifies RSA signature round-trip correctness and minimum key length.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module fg_rsa_functional (
  fg_rsa_if.props rsa
);

  import fg_pkg::*;

  // ==========================================================================
  // FG_RSA_FUNC_001 — Signature Round-Trip Correctness
  // ==========================================================================
  // Sign(M) followed by Verify(Sign(M)) must succeed. If a message is
  // signed and then the signature is verified with the corresponding
  // public key, the verification must produce a valid result.
  //
  // Compliance: PCI-DSS 3.5.1
  // ==========================================================================

  // Capture signed output for round-trip verification
  logic [2047:0] captured_message;
  logic [2047:0] captured_signature;
  logic [2047:0] captured_modulus;
  logic          signature_captured;
  logic          awaiting_verify;

  always_ff @(posedge rsa.clk or negedge rsa.rst_n) begin
    if (!rsa.rst_n) begin
      captured_message   <= '0;
      captured_signature <= '0;
      captured_modulus   <= '0;
      signature_captured <= 1'b0;
      awaiting_verify    <= 1'b0;
    end else begin
      // Capture signing inputs
      if (rsa.start && rsa.mode_sign && !rsa.busy) begin
        captured_message <= rsa.message;
        captured_modulus <= rsa.modulus;
        signature_captured <= 1'b0;
        awaiting_verify <= 1'b0;
      end
      // Capture signature output
      if (rsa.done && !rsa.error && rsa.mode_sign) begin
        captured_signature <= rsa.result_data;
        signature_captured <= 1'b1;
      end
      // Track verification of captured signature
      if (rsa.start && !rsa.mode_sign && signature_captured &&
          rsa.message == captured_signature && rsa.modulus == captured_modulus) begin
        awaiting_verify <= 1'b1;
      end
      if (rsa.done && awaiting_verify) begin
        awaiting_verify    <= 1'b0;
        signature_captured <= 1'b0;
      end
    end
  end

  property p_rsa_func_001;
    @(posedge rsa.clk) disable iff (!rsa.rst_n)
    (rsa.done && !rsa.error && awaiting_verify)
    |-> rsa.result_valid;
  endproperty

  FG_RSA_FUNC_001: assert property (p_rsa_func_001)
    else $error("FG_RSA_FUNC_001 FAIL: Verify(Sign(M)) did not succeed — signature round-trip broken");

  // Operation must complete within bounded time
  property p_rsa_func_001_completion;
    @(posedge rsa.clk) disable iff (!rsa.rst_n)
    (rsa.start && !rsa.busy)
    |-> ##[1:FG_RSA_MAX_LATENCY] (rsa.done);
  endproperty

  FG_RSA_FUNC_001_COMP: assert property (p_rsa_func_001_completion)
    else $error("FG_RSA_FUNC_001 FAIL: RSA operation did not complete within %0d cycles",
                FG_RSA_MAX_LATENCY);

  // ==========================================================================
  // FG_RSA_FUNC_002 — Minimum Key Length Enforcement
  // ==========================================================================
  // The module must reject key lengths below 2048 bits. Shorter RSA keys
  // are considered cryptographically weak for financial applications.
  //
  // Compliance: PCI-DSS 3.6.1
  // ==========================================================================

  property p_rsa_func_002;
    @(posedge rsa.clk) disable iff (!rsa.rst_n)
    (rsa.start && (rsa.key_length < FG_RSA_MIN_KEY_LEN))
    |-> ##[0:1] rsa.error;
  endproperty

  FG_RSA_FUNC_002: assert property (p_rsa_func_002)
    else $error("FG_RSA_FUNC_002 FAIL: Module accepted key shorter than %0d bits",
                FG_RSA_MIN_KEY_LEN);

  // ==========================================================================
  // Coverage
  // ==========================================================================

  cover property (@(posedge rsa.clk) rsa.start && rsa.mode_sign && !rsa.busy);
  cover property (@(posedge rsa.clk) rsa.done && !rsa.error && rsa.mode_sign);
  cover property (@(posedge rsa.clk) rsa.done && awaiting_verify && rsa.result_valid);
  cover property (@(posedge rsa.clk) rsa.start && rsa.key_length < FG_RSA_MIN_KEY_LEN);

endmodule : fg_rsa_functional
