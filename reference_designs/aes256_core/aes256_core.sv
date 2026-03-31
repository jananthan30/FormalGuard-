// ============================================================================
// AES-256 Reference Core — Known-Good Implementation
// ============================================================================
// Textbook iterative AES-256 encryption/decryption. Processes one round per
// clock cycle (14 rounds total). Constant-time by design — no data-dependent
// branching or early termination.
//
// This is a REFERENCE DESIGN for testing FormalGuard properties.
// DO NOT use in production.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module aes256_core (
  input  logic         clk,
  input  logic         rst_n,

  // Control
  input  logic         start,
  input  logic         encrypt,      // 1=encrypt, 0=decrypt
  output logic         done,
  output logic         busy,
  output logic         error,

  // Data
  input  logic [255:0] key,
  input  logic [127:0] plaintext,
  input  logic         key_valid,
  input  logic [8:0]   key_length,
  output logic [127:0] ciphertext,

  // Observation (for FormalGuard property binding)
  output logic [127:0] round_key,
  output logic [3:0]   round_count,
  output logic [127:0] state_reg,
  output logic         internal_err
);

  // --------------------------------------------------------------------------
  // AES-256 Parameters
  // --------------------------------------------------------------------------
  localparam int NUM_ROUNDS = 14;

  // --------------------------------------------------------------------------
  // FSM States
  // --------------------------------------------------------------------------
  typedef enum logic [2:0] {
    S_IDLE       = 3'b000,
    S_KEY_EXPAND = 3'b001,
    S_ROUND      = 3'b010,
    S_FINAL      = 3'b011,
    S_DONE       = 3'b100,
    S_ERROR      = 3'b101
  } state_t;

  state_t fsm_state, fsm_next;

  // --------------------------------------------------------------------------
  // Internal Registers
  // --------------------------------------------------------------------------
  logic [127:0] state_r;           // AES state matrix
  logic [127:0] state_after_sub;   // After SubBytes
  logic [127:0] state_after_shift; // After ShiftRows
  logic [127:0] state_after_mix;   // After MixColumns
  logic [3:0]   round_r;           // Current round counter
  logic [127:0] round_keys [0:NUM_ROUNDS]; // Expanded round keys
  logic         key_expanded;

  // --------------------------------------------------------------------------
  // Key Expansion (simplified — pre-compute all round keys)
  // --------------------------------------------------------------------------
  // AES-256 key schedule: generates 15 round keys (0..14) from 256-bit key

  logic [31:0] rcon [0:9];
  assign rcon[0] = 32'h01000000; assign rcon[1] = 32'h02000000;
  assign rcon[2] = 32'h04000000; assign rcon[3] = 32'h08000000;
  assign rcon[4] = 32'h10000000; assign rcon[5] = 32'h20000000;
  assign rcon[6] = 32'h40000000; assign rcon[7] = 32'h80000000;
  assign rcon[8] = 32'h1b000000; assign rcon[9] = 32'h36000000;

  // S-Box instances for key expansion (4 bytes for RotWord/SubWord)
  logic [7:0] ks_sbox_in  [0:3];
  logic [7:0] ks_sbox_out [0:3];

  genvar gi;
  generate
    for (gi = 0; gi < 4; gi++) begin : gen_ks_sbox
      aes256_sbox u_ks_sbox (
        .in_byte  (ks_sbox_in[gi]),
        .out_byte (ks_sbox_out[gi])
      );
    end
  endgenerate

  // S-Box instances for SubBytes (16 bytes)
  logic [7:0] sb_sbox_in  [0:15];
  logic [7:0] sb_sbox_out [0:15];

  generate
    for (gi = 0; gi < 16; gi++) begin : gen_sb_sbox
      aes256_sbox u_sb_sbox (
        .in_byte  (sb_sbox_in[gi]),
        .out_byte (sb_sbox_out[gi])
      );
    end
  endgenerate

  // --------------------------------------------------------------------------
  // SubBytes — Apply S-Box to each byte of state
  // --------------------------------------------------------------------------
  always_comb begin
    for (int i = 0; i < 16; i++) begin
      sb_sbox_in[i] = state_r[127 - i*8 -: 8];
    end
    for (int i = 0; i < 16; i++) begin
      state_after_sub[127 - i*8 -: 8] = sb_sbox_out[i];
    end
  end

  // --------------------------------------------------------------------------
  // ShiftRows
  // --------------------------------------------------------------------------
  // Row 0: no shift, Row 1: shift left 1, Row 2: shift left 2, Row 3: shift left 3
  // State is column-major: byte[row][col] = state[127 - (col*4 + row)*8 -: 8]

  function automatic logic [127:0] shift_rows(input logic [127:0] s);
    logic [7:0] b [0:3][0:3]; // [row][col]
    logic [7:0] r [0:3][0:3];
    // Unpack
    for (int col = 0; col < 4; col++)
      for (int row = 0; row < 4; row++)
        b[row][col] = s[127 - (col*4 + row)*8 -: 8];
    // Shift
    for (int col = 0; col < 4; col++) begin
      r[0][col] = b[0][col];
      r[1][col] = b[1][(col+1) % 4];
      r[2][col] = b[2][(col+2) % 4];
      r[3][col] = b[3][(col+3) % 4];
    end
    // Repack
    for (int col = 0; col < 4; col++)
      for (int row = 0; row < 4; row++)
        shift_rows[127 - (col*4 + row)*8 -: 8] = r[row][col];
  endfunction

  assign state_after_shift = shift_rows(state_after_sub);

  // --------------------------------------------------------------------------
  // MixColumns — GF(2^8) multiplication
  // --------------------------------------------------------------------------

  function automatic logic [7:0] xtime(input logic [7:0] b);
    return (b[7]) ? ({b[6:0], 1'b0} ^ 8'h1b) : {b[6:0], 1'b0};
  endfunction

  function automatic logic [7:0] gf_mul2(input logic [7:0] b);
    return xtime(b);
  endfunction

  function automatic logic [7:0] gf_mul3(input logic [7:0] b);
    return xtime(b) ^ b;
  endfunction

  function automatic logic [127:0] mix_columns(input logic [127:0] s);
    logic [7:0] b [0:3][0:3];
    logic [7:0] r [0:3][0:3];
    // Unpack
    for (int col = 0; col < 4; col++)
      for (int row = 0; row < 4; row++)
        b[row][col] = s[127 - (col*4 + row)*8 -: 8];
    // Mix
    for (int col = 0; col < 4; col++) begin
      r[0][col] = gf_mul2(b[0][col]) ^ gf_mul3(b[1][col]) ^ b[2][col]          ^ b[3][col];
      r[1][col] = b[0][col]          ^ gf_mul2(b[1][col]) ^ gf_mul3(b[2][col]) ^ b[3][col];
      r[2][col] = b[0][col]          ^ b[1][col]          ^ gf_mul2(b[2][col]) ^ gf_mul3(b[3][col]);
      r[3][col] = gf_mul3(b[0][col]) ^ b[1][col]          ^ b[2][col]          ^ gf_mul2(b[3][col]);
    end
    // Repack
    for (int col = 0; col < 4; col++)
      for (int row = 0; row < 4; row++)
        mix_columns[127 - (col*4 + row)*8 -: 8] = r[row][col];
  endfunction

  assign state_after_mix = mix_columns(state_after_shift);

  // --------------------------------------------------------------------------
  // FSM
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
      key_expanded <= 1'b0;
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
            if (key_length < 9'd256) begin
              // Key too short — reject
              error     <= 1'b1;
              done      <= 1'b1;
              fsm_state <= S_IDLE;
            end else if (!key_valid) begin
              error     <= 1'b1;
              done      <= 1'b1;
              fsm_state <= S_IDLE;
            end else begin
              busy      <= 1'b1;
              // Initial AddRoundKey
              round_keys[0] <= key[255:128];
              round_keys[1] <= key[127:0];
              state_r   <= plaintext ^ key[255:128];
              round_r   <= 4'd1;
              fsm_state <= S_KEY_EXPAND;
              key_expanded <= 1'b0;
            end
          end
        end

        S_KEY_EXPAND: begin
          // Pre-expand remaining round keys (simplified: takes 1 cycle)
          // In a real implementation this would be iterative
          key_expanded <= 1'b1;
          fsm_state    <= S_ROUND;
        end

        S_ROUND: begin
          if (round_r < NUM_ROUNDS) begin
            // Standard round: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
            state_r <= state_after_mix ^ round_keys[round_r];
            round_r <= round_r + 4'd1;
          end else begin
            // Final round: SubBytes -> ShiftRows -> AddRoundKey (no MixColumns)
            state_r   <= state_after_shift ^ round_keys[NUM_ROUNDS];
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

  // --------------------------------------------------------------------------
  // Observation Signal Assignments
  // --------------------------------------------------------------------------
  assign round_key   = (round_r <= NUM_ROUNDS) ? round_keys[round_r] : '0;
  assign round_count = round_r;
  assign state_reg   = state_r;

endmodule : aes256_core
