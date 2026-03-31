// ============================================================================
// FormalGuard — RSA Timing Properties (Side-Channel Resistance)
// ============================================================================
// Property ID:  FG_RSA_TIME_001
// Compliance:   PCI-DSS 3.5.1
//
// Verifies that modular exponentiation executes in constant time,
// preventing timing attacks that leak private key bits.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module fg_rsa_timing (
  fg_rsa_if.props rsa
);

  import fg_pkg::*;

  // ==========================================================================
  // FG_RSA_TIME_001 — Constant-Time Modular Exponentiation
  // ==========================================================================
  // The execution time of modular exponentiation must be independent of
  // the exponent (private key) value. Square-and-multiply implementations
  // that skip multiplications for zero bits leak the Hamming weight and
  // bit pattern of the private key.
  //
  // Compliance: PCI-DSS 3.5.1
  // ==========================================================================

  logic [31:0] op_cycle_count;
  logic [31:0] last_op_cycles;
  logic        last_op_valid;
  logic        counting;
  logic [2047:0] prev_exponent;
  logic [2047:0] curr_exponent;

  always_ff @(posedge rsa.clk or negedge rsa.rst_n) begin
    if (!rsa.rst_n) begin
      op_cycle_count <= '0;
      last_op_cycles <= '0;
      last_op_valid  <= 1'b0;
      counting       <= 1'b0;
      prev_exponent  <= '0;
      curr_exponent  <= '0;
    end else begin
      if (rsa.start && !rsa.busy) begin
        op_cycle_count <= 32'd1;
        counting       <= 1'b1;
        curr_exponent  <= rsa.exponent;
      end else if (counting && !rsa.done) begin
        op_cycle_count <= op_cycle_count + 32'd1;
      end

      if (rsa.done && counting) begin
        last_op_cycles <= op_cycle_count;
        last_op_valid  <= 1'b1;
        counting       <= 1'b0;
        prev_exponent  <= curr_exponent;
      end
    end
  end

  property p_rsa_time_001;
    @(posedge rsa.clk) disable iff (!rsa.rst_n)
    (rsa.done && counting && last_op_valid && !rsa.error &&
     curr_exponent != prev_exponent)
    |-> (op_cycle_count == last_op_cycles);
  endproperty

  FG_RSA_TIME_001: assert property (p_rsa_time_001)
    else $error("FG_RSA_TIME_001 FAIL: Exponent-dependent timing detected — %0d vs %0d cycles",
                op_cycle_count, last_op_cycles);

  // ==========================================================================
  // Coverage
  // ==========================================================================

  cover property (@(posedge rsa.clk) rsa.done && counting && last_op_valid);

endmodule : fg_rsa_timing
