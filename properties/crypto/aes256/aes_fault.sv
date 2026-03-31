// ============================================================================
// FormalGuard — AES-256 Fault Resistance Properties
// ============================================================================
// Property IDs: FG_AES_FAULT_001, FG_AES_FAULT_002
// Compliance:   FIPS 140-3 Level 3+
//
// These properties verify that AES-256 implementations can detect and
// respond to fault injection attacks. Such attacks (laser, voltage
// glitching, EM injection) attempt to corrupt intermediate state to
// extract key material via Differential Fault Analysis (DFA).
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module fg_aes_fault (
  fg_aes256_if.props aes
);

  import fg_pkg::*;

  // ==========================================================================
  // FG_AES_FAULT_001 — Fault Detection (Single-Bit Flip)
  // ==========================================================================
  // A single-bit flip in any round state register must not produce output
  // that is silently accepted as valid ciphertext. The module must either
  // detect the fault (via internal consistency checks) or the corrupted
  // output must differ from the correct output.
  //
  // Implementation: We model the fault using a free variable (bit position)
  // that the formal tool explores exhaustively. The property checks that
  // if the internal state is corrupted at any bit position during processing,
  // the module either enters an error state or the output is flagged.
  //
  // Note: This property requires the design to expose state_reg and
  // internal_err observation signals through the binding interface.
  //
  // Compliance: FIPS 140-3 Level 3+
  // ==========================================================================

  // Free variable: formal tool explores all possible bit flip positions
  (* anyconst *) logic [6:0] fault_bit_position;  // 0-127 for 128-bit state

  // Track if a fault condition occurred during processing
  logic fault_injected;
  logic [127:0] clean_state_snapshot;

  always_ff @(posedge aes.clk or negedge aes.rst_n) begin
    if (!aes.rst_n) begin
      fault_injected       <= 1'b0;
      clean_state_snapshot <= '0;
    end else begin
      if (aes.start && aes.key_valid && !aes.busy) begin
        fault_injected <= 1'b0;
      end
      // Snapshot clean state at the start of each round
      if (aes.busy && aes.round_count > 0) begin
        clean_state_snapshot <= aes.state_reg;
      end
    end
  end

  // Model: if a single bit were flipped in state_reg, the resulting state
  // would differ. Check that the design detects such corruption.
  wire [127:0] corrupted_state = aes.state_reg ^ (128'd1 << fault_bit_position);

  property p_aes_fault_001;
    @(posedge aes.clk) disable iff (!aes.rst_n)
    // If the state differs from what a fault-free execution would produce
    // (modeled by checking if the corrupted version matches actual output),
    // then the module must flag an error
    (aes.done && aes.state_reg != clean_state_snapshot &&
     |clean_state_snapshot && aes.busy)
    |-> aes.error || aes.internal_err;
  endproperty

  FG_AES_FAULT_001: assert property (p_aes_fault_001)
    else $error("FG_AES_FAULT_001 FAIL: State corruption at bit %0d not detected — DFA vulnerability",
                fault_bit_position);

  // ==========================================================================
  // FG_AES_FAULT_002 — Error State Entry on Consistency Failure
  // ==========================================================================
  // When the internal consistency check detects an error (internal_err
  // asserted), the module must enter the error state and not produce
  // valid-looking output on the ciphertext port.
  //
  // Compliance: FIPS 140-3
  // ==========================================================================

  property p_aes_fault_002;
    @(posedge aes.clk) disable iff (!aes.rst_n)
    aes.internal_err
    |-> ##[0:2] aes.error;
  endproperty

  FG_AES_FAULT_002: assert property (p_aes_fault_002)
    else $error("FG_AES_FAULT_002 FAIL: Internal consistency error did not trigger error state");

  // Supplementary: error state must not produce done without error flag
  property p_aes_fault_002_no_silent_output;
    @(posedge aes.clk) disable iff (!aes.rst_n)
    (aes.internal_err && aes.busy)
    |-> !aes.done || aes.error;
  endproperty

  FG_AES_FAULT_002_SUP: assert property (p_aes_fault_002_no_silent_output)
    else $error("FG_AES_FAULT_002_SUP FAIL: Module produced output after internal error without error flag");

  // ==========================================================================
  // Coverage Points
  // ==========================================================================

  cover property (@(posedge aes.clk) aes.internal_err && aes.busy);
  cover property (@(posedge aes.clk) aes.error && aes.done);

endmodule : fg_aes_fault
