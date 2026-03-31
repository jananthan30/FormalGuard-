// ============================================================================
// Vulnerable AES-256 — Intentional Timing Side-Channel
// ============================================================================
// This design contains a DELIBERATE vulnerability: it short-circuits
// (early terminates) when it detects all-zero bytes in the key. This
// creates a timing side-channel that leaks information about key values.
//
// Purpose: Demonstrate that FG_AES_TIME_001 and FG_AES_TIME_003
// catch timing side-channel vulnerabilities.
//
// Expected results:
//   - FG_AES_FUNC_001: PASS (operations still complete correctly)
//   - FG_AES_FUNC_004: PASS (key length is still enforced)
//   - FG_AES_TIME_001: FAIL (key-dependent timing detected)
//   - FG_AES_TIME_003: FAIL (early termination detected)
//
// This is a REFERENCE DESIGN for testing FormalGuard properties.
// DO NOT use in production. This design is INTENTIONALLY INSECURE.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module vuln_aes (
  input  logic         clk,
  input  logic         rst_n,

  // Control
  input  logic         start,
  input  logic         encrypt,
  output logic         done,
  output logic         busy,
  output logic         error,

  // Data
  input  logic [255:0] key,
  input  logic [127:0] plaintext,
  input  logic         key_valid,
  input  logic [8:0]   key_length,
  output logic [127:0] ciphertext,

  // Observation
  output logic [127:0] round_key,
  output logic [3:0]   round_count,
  output logic [127:0] state_reg,
  output logic         internal_err
);

  localparam int NUM_ROUNDS = 14;

  typedef enum logic [2:0] {
    S_IDLE  = 3'b000,
    S_ROUND = 3'b010,
    S_DONE  = 3'b100,
    S_ERROR = 3'b101
  } state_t;

  state_t fsm_state;
  logic [127:0] state_r;
  logic [3:0]   round_r;
  logic [127:0] round_keys [0:NUM_ROUNDS];

  // ========================================================================
  // VULNERABILITY: Check if key has zero bytes and skip rounds
  // ========================================================================
  // This optimization is WRONG from a security perspective. It creates a
  // timing side-channel where keys with zero bytes process faster.
  logic key_has_zero_bytes;

  always_comb begin
    key_has_zero_bytes = 1'b0;
    for (int i = 0; i < 32; i++) begin
      if (key[i*8 +: 8] == 8'h00)
        key_has_zero_bytes = 1'b1;
    end
  end

  // Determine how many rounds to actually execute
  // BUG: Skip some rounds for "simple" keys (those with zero bytes)
  logic [3:0] effective_rounds;
  assign effective_rounds = key_has_zero_bytes ? 4'd8 : NUM_ROUNDS[3:0];

  // --------------------------------------------------------------------------
  // Simplified round function (same S-box as reference design)
  // --------------------------------------------------------------------------

  logic [127:0] state_after_sub;

  // S-Box instances
  logic [7:0] sb_in  [0:15];
  logic [7:0] sb_out [0:15];

  genvar gi;
  generate
    for (gi = 0; gi < 16; gi++) begin : gen_sbox
      aes256_sbox u_sbox (
        .in_byte  (sb_in[gi]),
        .out_byte (sb_out[gi])
      );
    end
  endgenerate

  always_comb begin
    for (int i = 0; i < 16; i++) begin
      sb_in[i] = state_r[127 - i*8 -: 8];
    end
    for (int i = 0; i < 16; i++) begin
      state_after_sub[127 - i*8 -: 8] = sb_out[i];
    end
  end

  // --------------------------------------------------------------------------
  // FSM (with timing vulnerability)
  // --------------------------------------------------------------------------

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      fsm_state    <= S_IDLE;
      state_r      <= '0;
      round_r      <= '0;
      done         <= 1'b0;
      busy         <= 1'b0;
      error        <= 1'b0;
      ciphertext   <= '0;
      internal_err <= 1'b0;
      for (int i = 0; i <= NUM_ROUNDS; i++)
        round_keys[i] <= '0;
    end else begin
      done  <= 1'b0;
      error <= 1'b0;

      case (fsm_state)
        S_IDLE: begin
          busy <= 1'b0;
          if (start) begin
            if (key_length < 9'd256 || !key_valid) begin
              error     <= 1'b1;
              done      <= 1'b1;
              fsm_state <= S_IDLE;
            end else begin
              busy      <= 1'b1;
              round_keys[0] <= key[255:128];
              state_r   <= plaintext ^ key[255:128];
              round_r   <= 4'd1;
              fsm_state <= S_ROUND;
            end
          end
        end

        S_ROUND: begin
          // VULNERABILITY: Use effective_rounds instead of NUM_ROUNDS
          // Keys with zero bytes get fewer rounds, completing faster
          if (round_r < effective_rounds) begin
            state_r <= state_after_sub ^ round_keys[round_r];
            round_r <= round_r + 4'd1;
          end else begin
            state_r   <= state_after_sub ^ round_keys[round_r];
            fsm_state <= S_DONE;
          end
        end

        S_DONE: begin
          ciphertext <= state_r;
          done       <= 1'b1;
          busy       <= 1'b0;
          fsm_state  <= S_IDLE;
        end

        S_ERROR: begin
          error      <= 1'b1;
          done       <= 1'b1;
          busy       <= 1'b0;
          fsm_state  <= S_IDLE;
        end

        default: begin
          fsm_state  <= S_ERROR;
          internal_err <= 1'b1;
        end
      endcase
    end
  end

  // Observation signals
  assign round_key   = (round_r <= NUM_ROUNDS) ? round_keys[round_r] : '0;
  assign round_count = round_r;
  assign state_reg   = state_r;

endmodule : vuln_aes
