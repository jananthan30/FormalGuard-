// ============================================================================
// Simple HSM — Known-Good Reference Implementation
// ============================================================================
// FSM-based Hardware Security Module with key storage, authentication,
// dual-control, and tamper response. Implements all security properties
// correctly for testing FormalGuard HSM properties.
//
// This is a REFERENCE DESIGN for testing FormalGuard properties.
// DO NOT use in production.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module simple_hsm
  import fg_pkg::*;
(
  input  logic         clk,
  input  logic         rst_n,

  // Key Management
  input  logic         key_gen_req,
  output logic         key_gen_done,
  input  logic [3:0]   key_id,
  output logic [255:0] key_data,
  output logic [8:0]   key_length,
  output logic         key_valid,

  input  logic         key_destroy_req,
  output logic         key_destroy_done,

  input  logic         key_rotate_req,
  output logic         key_rotate_done,
  output logic         new_key_active,
  output logic         old_key_invalid,

  // Access Control
  input  logic         auth_req,
  output logic         auth_granted,
  output logic         auth_failed,
  input  hsm_role_t    auth_role,
  output logic [3:0]   fail_count,
  output logic         locked,

  input  logic         dual_auth_req,
  output logic         dual_auth_granted,
  output logic         dual_control_active,

  // Crypto Operations
  input  logic         crypto_op_req,
  output logic         crypto_op_done,
  output logic         crypto_op_valid,

  // Tamper
  input  logic         tamper_detect,
  output logic         zeroize_active,
  output logic         zeroize_done,
  input  logic         zeroize_cmd,

  // Observation
  output logic [255:0] key_store [0:FG_HSM_KEY_SLOTS-1],
  output logic [255:0] ext_bus_data,
  output logic [255:0] ram_content,
  output hsm_state_t   state
);

  // --------------------------------------------------------------------------
  // Internal State
  // --------------------------------------------------------------------------
  hsm_state_t current_state, next_state;
  logic       authenticated;
  logic       dual_authenticated;
  logic [3:0] zeroize_counter;
  logic [3:0] op_counter;
  logic [3:0] destroy_target;

  // PRNG for key generation (simplified — NOT cryptographically secure)
  logic [255:0] prng_state;

  assign state = current_state;

  // --------------------------------------------------------------------------
  // FSM
  // --------------------------------------------------------------------------
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      current_state      <= HSM_IDLE;
      authenticated      <= 1'b0;
      dual_authenticated <= 1'b0;
      fail_count         <= '0;
      locked             <= 1'b0;
      zeroize_active     <= 1'b0;
      zeroize_done       <= 1'b0;
      zeroize_counter    <= '0;
      key_gen_done       <= 1'b0;
      key_destroy_done   <= 1'b0;
      key_rotate_done    <= 1'b0;
      new_key_active     <= 1'b0;
      old_key_invalid    <= 1'b0;
      auth_granted       <= 1'b0;
      auth_failed        <= 1'b0;
      dual_auth_granted  <= 1'b0;
      dual_control_active <= 1'b0;
      crypto_op_done     <= 1'b0;
      crypto_op_valid    <= 1'b0;
      ext_bus_data       <= '0;
      ram_content        <= '0;
      key_data           <= '0;
      key_length         <= '0;
      key_valid          <= 1'b0;
      op_counter         <= '0;
      destroy_target     <= '0;
      prng_state         <= 256'hDEADBEEF_CAFEBABE_12345678_9ABCDEF0_FEEDFACE_BADDCAFE_01234567_89ABCDEF;

      for (int i = 0; i < FG_HSM_KEY_SLOTS; i++)
        key_store[i] <= '0;

    end else begin
      // Clear single-cycle pulses
      key_gen_done      <= 1'b0;
      key_destroy_done  <= 1'b0;
      key_rotate_done   <= 1'b0;
      auth_granted      <= 1'b0;
      auth_failed       <= 1'b0;
      dual_auth_granted <= 1'b0;
      crypto_op_done    <= 1'b0;
      crypto_op_valid   <= 1'b0;
      zeroize_done      <= 1'b0;

      // --- Tamper override: highest priority ---
      if (tamper_detect && current_state != HSM_TAMPERED) begin
        current_state   <= HSM_ZEROIZE;
        zeroize_active  <= 1'b1;
        zeroize_counter <= '0;
        authenticated   <= 1'b0;
      end

      else case (current_state)

        HSM_IDLE: begin
          if (auth_req && !locked) begin
            current_state <= HSM_AUTH;
          end
        end

        HSM_AUTH: begin
          // Simplified auth: accept any non-NONE role
          if (auth_role != ROLE_NONE) begin
            auth_granted       <= 1'b1;
            authenticated      <= 1'b1;
            fail_count         <= '0;  // Reset on success
            current_state      <= HSM_READY;
          end else begin
            auth_failed <= 1'b1;
            fail_count  <= fail_count + 4'd1;
            if (fail_count + 4'd1 >= FG_HSM_MAX_AUTH_FAIL) begin
              locked        <= 1'b1;
              current_state <= HSM_LOCKED;
            end else begin
              current_state <= HSM_IDLE;
            end
          end
        end

        HSM_READY: begin
          // Handle dual auth
          if (dual_auth_req && authenticated) begin
            dual_auth_granted   <= 1'b1;
            dual_authenticated  <= 1'b1;
            dual_control_active <= 1'b1;
          end

          // Key generation
          if (key_gen_req) begin
            current_state <= HSM_KEY_GEN;
            op_counter    <= '0;
          end

          // Key destruction (requires dual control)
          if (key_destroy_req && dual_control_active) begin
            destroy_target  <= key_id;
            current_state   <= HSM_ZEROIZE;
            zeroize_active  <= 1'b1;
            zeroize_counter <= '0;
          end

          // Key rotation
          if (key_rotate_req) begin
            current_state  <= HSM_KEY_ROT;
            op_counter     <= '0;
            new_key_active <= 1'b0;
            old_key_invalid <= 1'b0;
          end

          // Crypto operation
          if (crypto_op_req && authenticated) begin
            current_state <= HSM_BUSY;
            op_counter    <= '0;
          end

          // Software zeroize command
          if (zeroize_cmd) begin
            current_state   <= HSM_ZEROIZE;
            zeroize_active  <= 1'b1;
            zeroize_counter <= '0;
          end
        end

        HSM_KEY_GEN: begin
          op_counter <= op_counter + 4'd1;
          // Generate key in 3 cycles
          if (op_counter == 4'd2) begin
            // PRNG advance (simplified)
            prng_state <= {prng_state[254:0], prng_state[255] ^ prng_state[128]};
            key_store[key_id] <= prng_state;
            key_data     <= prng_state;
            key_length   <= 9'd256;
            key_valid    <= 1'b1;
            key_gen_done <= 1'b1;
            current_state <= HSM_READY;
          end
        end

        HSM_KEY_ROT: begin
          op_counter <= op_counter + 4'd1;
          // Step 1: Generate new key and activate it
          if (op_counter == 4'd2) begin
            prng_state <= {prng_state[254:0], prng_state[255] ^ prng_state[0]};
            key_store[key_id] <= prng_state;
            new_key_active <= 1'b1;  // New key active FIRST
          end
          // Step 2: Then invalidate old key
          if (op_counter == 4'd4) begin
            old_key_invalid <= 1'b1;  // Old key invalid AFTER new is active
            key_rotate_done <= 1'b1;
            current_state   <= HSM_READY;
          end
        end

        HSM_BUSY: begin
          op_counter <= op_counter + 4'd1;
          // Crypto op takes 5 cycles
          if (op_counter == 4'd4) begin
            crypto_op_done  <= 1'b1;
            crypto_op_valid <= 1'b1;
            current_state   <= HSM_READY;
          end
          // IMPORTANT: ext_bus_data never gets key material
          ext_bus_data <= '0;
        end

        HSM_ZEROIZE: begin
          zeroize_counter <= zeroize_counter + 4'd1;

          // Progressively zero all key slots
          if (zeroize_counter < FG_HSM_KEY_SLOTS) begin
            key_store[zeroize_counter] <= '0;
          end

          // Complete zeroization
          if (zeroize_counter == FG_HSM_KEY_SLOTS) begin
            ram_content    <= '0;
            key_data       <= '0;
            zeroize_done   <= 1'b1;
            zeroize_active <= 1'b0;
            key_valid      <= 1'b0;
            authenticated  <= 1'b0;

            if (tamper_detect) begin
              current_state <= HSM_TAMPERED;
              key_destroy_done <= 1'b1;
            end else begin
              key_destroy_done <= 1'b1;
              current_state    <= HSM_READY;
            end
          end
        end

        HSM_TAMPERED: begin
          // Permanent state — no recovery
          current_state <= HSM_TAMPERED;
          // Ensure nothing leaks
          ext_bus_data <= '0;
        end

        HSM_LOCKED: begin
          // Stay locked until hardware reset
          if (auth_req) begin
            auth_failed <= 1'b1;
          end
        end

        HSM_ERROR: begin
          current_state <= HSM_ERROR;
        end

        default: begin
          current_state <= HSM_ERROR;
        end
      endcase
    end
  end

endmodule : simple_hsm
