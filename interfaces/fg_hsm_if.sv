// ============================================================================
// FormalGuard — HSM Binding Interface
// ============================================================================
// Standardized interface for binding FormalGuard HSM verification properties
// to any Hardware Security Module implementation. Covers key lifecycle,
// access control, and tamper response verification.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

interface fg_hsm_if;

  import fg_pkg::*;

  // ---- Clock and Reset ----
  logic         clk;
  logic         rst_n;

  // ---- HSM State ----
  hsm_state_t   state;

  // ---- Key Lifecycle Management ----
  logic         key_gen_req;        // Request to generate a new key
  logic         key_gen_done;       // Key generation complete
  logic [3:0]   key_id;            // Key slot identifier (0 to HSM_KEY_SLOTS-1)
  logic [255:0] key_data;          // Key material (internal observation)
  logic [8:0]   key_length;        // Generated key length in bits
  logic         key_valid;         // Key in selected slot is valid

  logic         key_destroy_req;    // Request to destroy (zeroize) a key
  logic         key_destroy_done;   // Destruction complete

  logic         key_rotate_req;     // Request to rotate a key
  logic         key_rotate_done;    // Rotation complete
  logic         new_key_active;     // New key has been activated
  logic         old_key_invalid;    // Old key has been invalidated

  // ---- Access Control ----
  logic         auth_req;           // Authentication request
  logic         auth_granted;       // Authentication successful
  logic         auth_failed;        // Authentication failed
  hsm_role_t    auth_role;          // Role of the authenticating entity
  logic [3:0]   fail_count;         // Consecutive authentication failure counter
  logic         locked;             // HSM locked due to excessive auth failures

  logic         dual_auth_req;      // Second authentication for dual-control operations
  logic         dual_auth_granted;  // Second auth successful
  logic         dual_control_active; // Dual-control mode is active

  // ---- Cryptographic Operations ----
  logic         crypto_op_req;      // Request a cryptographic operation
  logic         crypto_op_done;     // Operation complete
  logic         crypto_op_valid;    // Operation produced valid output

  // ---- Tamper Detection and Response ----
  logic         tamper_detect;      // Physical tamper signal (from sensors)
  logic         zeroize_active;     // Zeroization in progress
  logic         zeroize_done;       // Zeroization complete
  logic         zeroize_cmd;        // Software-initiated zeroization command

  // ---- Observation Signals ----
  // These allow deep verification of internal HSM state.
  logic [255:0] key_store [0:FG_HSM_KEY_SLOTS-1];  // All key storage slots
  logic [255:0] ext_bus_data;       // Data on external-facing bus (for key leak detection)
  logic [255:0] ram_content;        // Selected RAM content (for post-zeroize verification)

  // ---- Clocking Block ----
  clocking cb @(posedge clk);
    input rst_n, state;
    input key_gen_req, key_gen_done, key_id, key_data, key_length, key_valid;
    input key_destroy_req, key_destroy_done;
    input key_rotate_req, key_rotate_done, new_key_active, old_key_invalid;
    input auth_req, auth_granted, auth_failed, auth_role, fail_count, locked;
    input dual_auth_req, dual_auth_granted, dual_control_active;
    input crypto_op_req, crypto_op_done, crypto_op_valid;
    input tamper_detect, zeroize_active, zeroize_done, zeroize_cmd;
    input ext_bus_data, ram_content;
  endclocking

  // ---- Modports ----

  modport props (
    input  clk, rst_n, state,
    input  key_gen_req, key_gen_done, key_id, key_data, key_length, key_valid,
    input  key_destroy_req, key_destroy_done,
    input  key_rotate_req, key_rotate_done, new_key_active, old_key_invalid,
    input  auth_req, auth_granted, auth_failed, auth_role, fail_count, locked,
    input  dual_auth_req, dual_auth_granted, dual_control_active,
    input  crypto_op_req, crypto_op_done, crypto_op_valid,
    input  tamper_detect, zeroize_active, zeroize_done, zeroize_cmd,
    input  ext_bus_data, ram_content,
    clocking cb
  );

  modport dut (
    input  clk, rst_n,
    input  key_gen_req, key_destroy_req, key_rotate_req, key_id,
    input  auth_req, auth_role, dual_auth_req,
    input  crypto_op_req,
    input  tamper_detect, zeroize_cmd,
    output state,
    output key_gen_done, key_data, key_length, key_valid,
    output key_destroy_done,
    output key_rotate_done, new_key_active, old_key_invalid,
    output auth_granted, auth_failed, fail_count, locked,
    output dual_auth_granted, dual_control_active,
    output crypto_op_done, crypto_op_valid,
    output zeroize_active, zeroize_done,
    output ext_bus_data, ram_content
  );

endinterface : fg_hsm_if
