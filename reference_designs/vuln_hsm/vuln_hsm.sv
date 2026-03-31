// ============================================================================
// Vulnerable HSM — Intentional Incomplete Zeroization
// ============================================================================
// This design contains a DELIBERATE vulnerability: during key destruction,
// it only zeroes the first key slot instead of the targeted slot. After
// tamper-triggered zeroization, it fails to clear all key slots — only
// clearing slots 0-7 and leaving slots 8-15 with key material.
//
// Purpose: Demonstrate that FG_HSM_KEY_005 and FG_HSM_TAMP_003 catch
// incomplete zeroization vulnerabilities.
//
// Expected results:
//   - FG_HSM_KEY_001: PASS (key generation is correct)
//   - FG_HSM_KEY_003: PASS (zeroization completes in time)
//   - FG_HSM_KEY_005: FAIL (key remnants after destruction)
//   - FG_HSM_TAMP_001: PASS (tamper triggers zeroization promptly)
//   - FG_HSM_TAMP_003: FAIL (not all slots zeroed after tamper)
//
// This is a REFERENCE DESIGN for testing FormalGuard properties.
// DO NOT use in production. This design is INTENTIONALLY INSECURE.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module vuln_hsm
  import fg_pkg::*;
(
  input  logic         clk,
  input  logic         rst_n,

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

  input  logic         auth_req,
  output logic         auth_granted,
  output logic         auth_failed,
  input  hsm_role_t    auth_role,
  output logic [3:0]   fail_count,
  output logic         locked,

  input  logic         dual_auth_req,
  output logic         dual_auth_granted,
  output logic         dual_control_active,

  input  logic         crypto_op_req,
  output logic         crypto_op_done,
  output logic         crypto_op_valid,

  input  logic         tamper_detect,
  output logic         zeroize_active,
  output logic         zeroize_done,
  input  logic         zeroize_cmd,

  output logic [255:0] key_store [0:FG_HSM_KEY_SLOTS-1],
  output logic [255:0] ext_bus_data,
  output logic [255:0] ram_content,
  output hsm_state_t   state
);

  hsm_state_t current_state;
  logic       authenticated;
  logic [3:0] zeroize_counter;
  logic [3:0] op_counter;
  logic [3:0] destroy_target;
  logic [255:0] prng_state;
  logic       tamper_triggered;

  assign state = current_state;

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      current_state      <= HSM_IDLE;
      authenticated      <= 1'b0;
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
      tamper_triggered   <= 1'b0;
      prng_state         <= 256'hA5A5A5A5_5A5A5A5A_12345678_9ABCDEF0_FEEDFACE_BADDCAFE_01234567_89ABCDEF;

      for (int i = 0; i < FG_HSM_KEY_SLOTS; i++)
        key_store[i] <= '0;

    end else begin
      key_gen_done     <= 1'b0;
      key_destroy_done <= 1'b0;
      key_rotate_done  <= 1'b0;
      auth_granted     <= 1'b0;
      auth_failed      <= 1'b0;
      dual_auth_granted <= 1'b0;
      crypto_op_done   <= 1'b0;
      crypto_op_valid  <= 1'b0;
      zeroize_done     <= 1'b0;

      // Tamper override
      if (tamper_detect && current_state != HSM_TAMPERED) begin
        current_state  <= HSM_ZEROIZE;
        zeroize_active <= 1'b1;
        zeroize_counter <= '0;
        tamper_triggered <= 1'b1;
        authenticated  <= 1'b0;
      end

      else case (current_state)

        HSM_IDLE: begin
          if (auth_req && !locked) begin
            if (auth_role != ROLE_NONE) begin
              auth_granted  <= 1'b1;
              authenticated <= 1'b1;
              fail_count    <= '0;
              current_state <= HSM_READY;
            end else begin
              auth_failed <= 1'b1;
              fail_count  <= fail_count + 4'd1;
              if (fail_count + 4'd1 >= FG_HSM_MAX_AUTH_FAIL) begin
                locked        <= 1'b1;
                current_state <= HSM_LOCKED;
              end
            end
          end
        end

        HSM_READY: begin
          if (dual_auth_req && authenticated) begin
            dual_auth_granted   <= 1'b1;
            dual_control_active <= 1'b1;
          end

          if (key_gen_req) begin
            current_state <= HSM_KEY_GEN;
            op_counter    <= '0;
          end

          if (key_destroy_req && dual_control_active) begin
            destroy_target  <= key_id;
            current_state   <= HSM_ZEROIZE;
            zeroize_active  <= 1'b1;
            zeroize_counter <= '0;
            tamper_triggered <= 1'b0;
          end

          if (key_rotate_req) begin
            current_state   <= HSM_KEY_ROT;
            op_counter      <= '0;
            new_key_active  <= 1'b0;
            old_key_invalid <= 1'b0;
          end

          if (crypto_op_req && authenticated) begin
            current_state <= HSM_BUSY;
            op_counter    <= '0;
          end
        end

        HSM_KEY_GEN: begin
          op_counter <= op_counter + 4'd1;
          if (op_counter == 4'd2) begin
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
          if (op_counter == 4'd2) begin
            prng_state <= {prng_state[254:0], prng_state[255] ^ prng_state[0]};
            key_store[key_id] <= prng_state;
            new_key_active <= 1'b1;
          end
          if (op_counter == 4'd4) begin
            old_key_invalid <= 1'b1;
            key_rotate_done <= 1'b1;
            current_state   <= HSM_READY;
          end
        end

        HSM_BUSY: begin
          op_counter <= op_counter + 4'd1;
          if (op_counter == 4'd4) begin
            crypto_op_done  <= 1'b1;
            crypto_op_valid <= 1'b1;
            current_state   <= HSM_READY;
          end
          ext_bus_data <= '0;
        end

        HSM_ZEROIZE: begin
          zeroize_counter <= zeroize_counter + 4'd1;

          // ================================================================
          // VULNERABILITY: Only clear slots 0-7, leave 8-15 intact
          // ================================================================
          // BUG: On tamper, should clear ALL 16 slots. Instead only
          // clears the first 8. Slots 8-15 retain key material.
          //
          // For single-key destruction, BUG: clears slot 0 instead of
          // the target slot.
          // ================================================================
          if (tamper_triggered) begin
            // BUG: Only zeroes first half of key store
            if (zeroize_counter < 4'd8) begin
              key_store[zeroize_counter] <= '0;
            end
          end else begin
            // BUG: Always zeroes slot 0 instead of destroy_target
            if (zeroize_counter == 4'd0) begin
              key_store[0] <= '0;  // Should be key_store[destroy_target]
            end
          end

          if (zeroize_counter == 4'd8) begin
            // BUG: ram_content not fully cleared
            ram_content    <= '0;
            zeroize_done   <= 1'b1;
            zeroize_active <= 1'b0;

            if (tamper_triggered) begin
              current_state    <= HSM_TAMPERED;
              key_destroy_done <= 1'b1;
            end else begin
              key_destroy_done <= 1'b1;
              current_state    <= HSM_READY;
            end
          end
        end

        HSM_TAMPERED: begin
          current_state <= HSM_TAMPERED;
          ext_bus_data  <= '0;
        end

        HSM_LOCKED: begin
          if (auth_req) auth_failed <= 1'b1;
        end

        default: current_state <= HSM_ERROR;
      endcase
    end
  end

endmodule : vuln_hsm
