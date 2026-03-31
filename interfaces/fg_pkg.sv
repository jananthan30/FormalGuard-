// ============================================================================
// FormalGuard — Shared Package
// ============================================================================
// Common parameters, types, and utility functions used across all FormalGuard
// property libraries and reference designs.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

package fg_pkg;

  // --------------------------------------------------------------------------
  // Global Timing Parameters (overridable per-design via defparam or bind)
  // --------------------------------------------------------------------------

  // AES-256
  parameter int FG_AES_KEY_LEN       = 256;
  parameter int FG_AES_BLOCK_LEN     = 128;
  parameter int FG_AES_ROUNDS        = 14;
  parameter int FG_AES_MAX_LATENCY   = 100;  // max cycles for one encrypt/decrypt
  parameter int FG_AES_MIN_LATENCY   = 14;   // minimum acceptable (no early exit)

  // RSA
  parameter int FG_RSA_MIN_KEY_LEN   = 2048;
  parameter int FG_RSA_MAX_LATENCY   = 10000;

  // SHA-256
  parameter int FG_SHA_BLOCK_LEN     = 512;
  parameter int FG_SHA_DIGEST_LEN    = 256;
  parameter int FG_SHA_MAX_LATENCY   = 200;

  // ECDSA
  parameter int FG_ECDSA_MAX_LATENCY = 5000;

  // HSM
  parameter int FG_HSM_ZEROIZE_MAX   = 50;   // max cycles for key zeroization
  parameter int FG_HSM_MAX_AUTH_FAIL = 5;     // lockout after N failures
  parameter int FG_HSM_KEY_SLOTS     = 16;    // number of key storage slots

  // Transaction Pipeline
  parameter int FG_TX_PIPELINE_DEPTH = 4;
  parameter int FG_TX_MAX_LATENCY    = 50;

  // --------------------------------------------------------------------------
  // HSM State Machine Types
  // --------------------------------------------------------------------------

  typedef enum logic [3:0] {
    HSM_IDLE      = 4'h0,
    HSM_AUTH      = 4'h1,
    HSM_READY     = 4'h2,
    HSM_BUSY      = 4'h3,
    HSM_KEY_GEN   = 4'h4,
    HSM_KEY_LOAD  = 4'h5,
    HSM_KEY_ROT   = 4'h6,
    HSM_ZEROIZE   = 4'h7,
    HSM_TAMPERED  = 4'h8,
    HSM_LOCKED    = 4'h9,
    HSM_ERROR     = 4'hA
  } hsm_state_t;

  // --------------------------------------------------------------------------
  // Role Types for Access Control
  // --------------------------------------------------------------------------

  typedef enum logic [2:0] {
    ROLE_NONE     = 3'h0,
    ROLE_OPERATOR = 3'h1,
    ROLE_ADMIN    = 3'h2,
    ROLE_AUDITOR  = 3'h3,
    ROLE_SECURITY = 3'h4
  } hsm_role_t;

  // --------------------------------------------------------------------------
  // AES S-Box Lookup (FIPS 197, Section 5.1.1)
  // --------------------------------------------------------------------------
  // Used for golden-model verification of SubBytes transformation.

  function automatic logic [7:0] aes_sbox(input logic [7:0] in_byte);
    logic [7:0] sbox [0:255];
    sbox = '{
      8'h63, 8'h7c, 8'h77, 8'h7b, 8'hf2, 8'h6b, 8'h6f, 8'hc5,
      8'h30, 8'h01, 8'h67, 8'h2b, 8'hfe, 8'hd7, 8'hab, 8'h76,
      8'hca, 8'h82, 8'hc9, 8'h7d, 8'hfa, 8'h59, 8'h47, 8'hf0,
      8'had, 8'hd4, 8'ha2, 8'haf, 8'h9c, 8'ha4, 8'h72, 8'hc0,
      8'hb7, 8'hfd, 8'h93, 8'h26, 8'h36, 8'h3f, 8'hf7, 8'hcc,
      8'h34, 8'ha5, 8'he5, 8'hf1, 8'h71, 8'hd8, 8'h31, 8'h15,
      8'h04, 8'hc7, 8'h23, 8'hc3, 8'h18, 8'h96, 8'h05, 8'h9a,
      8'h07, 8'h12, 8'h80, 8'he2, 8'heb, 8'h27, 8'hb2, 8'h75,
      8'h09, 8'h83, 8'h2c, 8'h1a, 8'h1b, 8'h6e, 8'h5a, 8'ha0,
      8'h52, 8'h3b, 8'hd6, 8'hb3, 8'h29, 8'he3, 8'h2f, 8'h84,
      8'h53, 8'hd1, 8'h00, 8'hed, 8'h20, 8'hfc, 8'hb1, 8'h5b,
      8'h6a, 8'hcb, 8'hbe, 8'h39, 8'h4a, 8'h4c, 8'h58, 8'hcf,
      8'hd0, 8'hef, 8'haa, 8'hfb, 8'h43, 8'h4d, 8'h33, 8'h85,
      8'h45, 8'hf9, 8'h02, 8'h7f, 8'h50, 8'h3c, 8'h9f, 8'ha8,
      8'h51, 8'ha3, 8'h40, 8'h8f, 8'h92, 8'h9d, 8'h38, 8'hf5,
      8'hbc, 8'hb6, 8'hda, 8'h21, 8'h10, 8'hff, 8'hf3, 8'hd2,
      8'hcd, 8'h0c, 8'h13, 8'hec, 8'h5f, 8'h97, 8'h44, 8'h17,
      8'hc4, 8'ha7, 8'h7e, 8'h3d, 8'h64, 8'h5d, 8'h19, 8'h73,
      8'h60, 8'h81, 8'h4f, 8'hdc, 8'h22, 8'h2a, 8'h90, 8'h88,
      8'h46, 8'hee, 8'hb8, 8'h14, 8'hde, 8'h5e, 8'h0b, 8'hdb,
      8'he0, 8'h32, 8'h3a, 8'h0a, 8'h49, 8'h06, 8'h24, 8'h5c,
      8'hc2, 8'hd3, 8'hac, 8'h62, 8'h91, 8'h95, 8'he4, 8'h79,
      8'he7, 8'hc8, 8'h37, 8'h6d, 8'h8d, 8'hd5, 8'h4e, 8'ha9,
      8'h6c, 8'h56, 8'hf4, 8'hea, 8'h65, 8'h7a, 8'hae, 8'h08,
      8'hba, 8'h78, 8'h25, 8'h2e, 8'h1c, 8'ha6, 8'hb4, 8'hc6,
      8'he8, 8'hdd, 8'h74, 8'h1f, 8'h4b, 8'hbd, 8'h8b, 8'h8a,
      8'h70, 8'h3e, 8'hb5, 8'h66, 8'h48, 8'h03, 8'hf6, 8'h0e,
      8'h61, 8'h35, 8'h57, 8'hb9, 8'h86, 8'hc1, 8'h1d, 8'h9e,
      8'he1, 8'hf8, 8'h98, 8'h11, 8'h69, 8'hd9, 8'h8e, 8'h94,
      8'h9b, 8'h1e, 8'h87, 8'he9, 8'hce, 8'h55, 8'h28, 8'hdf,
      8'h8c, 8'ha1, 8'h89, 8'h0d, 8'hbf, 8'he6, 8'h42, 8'h68,
      8'h41, 8'h99, 8'h2d, 8'h0f, 8'hb0, 8'h54, 8'hbb, 8'h16
    };
    return sbox[in_byte];
  endfunction

  // --------------------------------------------------------------------------
  // Inverse AES S-Box (FIPS 197, Section 5.3.2)
  // --------------------------------------------------------------------------

  function automatic logic [7:0] aes_inv_sbox(input logic [7:0] in_byte);
    logic [7:0] inv_sbox [0:255];
    inv_sbox = '{
      8'h52, 8'h09, 8'h6a, 8'hd5, 8'h30, 8'h36, 8'ha5, 8'h38,
      8'hbf, 8'h40, 8'ha3, 8'h9e, 8'h81, 8'hf3, 8'hd7, 8'hfb,
      8'h7c, 8'he3, 8'h39, 8'h82, 8'h9b, 8'h2f, 8'hff, 8'h87,
      8'h34, 8'h8e, 8'h43, 8'h44, 8'hc4, 8'hde, 8'he9, 8'hcb,
      8'h54, 8'h7b, 8'h94, 8'h32, 8'ha6, 8'hc2, 8'h23, 8'h3d,
      8'hee, 8'h4c, 8'h95, 8'h0b, 8'h42, 8'hfa, 8'hc3, 8'h4e,
      8'h08, 8'h2e, 8'ha1, 8'h66, 8'h28, 8'hd9, 8'h24, 8'hb2,
      8'h76, 8'h5b, 8'ha2, 8'h49, 8'h6d, 8'h8b, 8'hd1, 8'h25,
      8'h72, 8'hf8, 8'hf6, 8'h64, 8'h86, 8'h68, 8'h98, 8'h16,
      8'hd4, 8'ha4, 8'h5c, 8'hcc, 8'h5d, 8'h65, 8'hb6, 8'h92,
      8'h6c, 8'h70, 8'h48, 8'h50, 8'hfd, 8'hed, 8'hb9, 8'hda,
      8'h5e, 8'h15, 8'h46, 8'h57, 8'ha7, 8'h8d, 8'h9d, 8'h84,
      8'h90, 8'hd8, 8'hab, 8'h00, 8'h8c, 8'hbc, 8'hd3, 8'h0a,
      8'hf7, 8'he4, 8'h58, 8'h05, 8'hb8, 8'hb3, 8'h45, 8'h06,
      8'hd0, 8'h2c, 8'h1e, 8'h8f, 8'hca, 8'h3f, 8'h0f, 8'h02,
      8'hc1, 8'haf, 8'hbd, 8'h03, 8'h01, 8'h13, 8'h8a, 8'h6b,
      8'h3a, 8'h91, 8'h11, 8'h41, 8'h4f, 8'h67, 8'hdc, 8'hea,
      8'h97, 8'hf2, 8'hcf, 8'hce, 8'hf0, 8'hb4, 8'he6, 8'h73,
      8'h96, 8'hac, 8'h74, 8'h22, 8'he7, 8'had, 8'h35, 8'h85,
      8'he2, 8'hf9, 8'h37, 8'he8, 8'h1c, 8'h75, 8'hdf, 8'h6e,
      8'h47, 8'hf1, 8'h1a, 8'h71, 8'h1d, 8'h29, 8'hc5, 8'h89,
      8'h6f, 8'hb7, 8'h62, 8'h0e, 8'haa, 8'h18, 8'hbe, 8'h1b,
      8'hfc, 8'h56, 8'h3e, 8'h4b, 8'hc6, 8'hd2, 8'h79, 8'h20,
      8'h9a, 8'hdb, 8'hc0, 8'hfe, 8'h78, 8'hcd, 8'h5a, 8'hf4,
      8'h1f, 8'hdd, 8'ha8, 8'h33, 8'h88, 8'h07, 8'hc7, 8'h31,
      8'hb1, 8'h12, 8'h10, 8'h59, 8'h27, 8'h80, 8'hec, 8'h5f,
      8'h60, 8'h51, 8'h7f, 8'ha9, 8'h19, 8'hb5, 8'h4a, 8'h0d,
      8'h2d, 8'he5, 8'h7a, 8'h9f, 8'h93, 8'hc9, 8'h9c, 8'hef,
      8'ha0, 8'he0, 8'h3b, 8'h4d, 8'hae, 8'h2a, 8'hf5, 8'hb0,
      8'hc8, 8'heb, 8'hbb, 8'h3c, 8'h83, 8'h53, 8'h99, 8'h61,
      8'h17, 8'h2b, 8'h04, 8'h7e, 8'hba, 8'h77, 8'hd6, 8'h26,
      8'he1, 8'h69, 8'h14, 8'h63, 8'h55, 8'h21, 8'h0c, 8'h7d
    };
    return inv_sbox[in_byte];
  endfunction

  // --------------------------------------------------------------------------
  // CRC-32 for Transaction Integrity Checking
  // --------------------------------------------------------------------------

  function automatic logic [31:0] crc32_byte(
    input logic [31:0] crc_in,
    input logic [7:0]  data_byte
  );
    logic [31:0] crc;
    integer i;
    crc = crc_in ^ {24'h0, data_byte};
    for (i = 0; i < 8; i++) begin
      if (crc[0])
        crc = (crc >> 1) ^ 32'hEDB88320;
      else
        crc = crc >> 1;
    end
    return crc;
  endfunction

endpackage : fg_pkg
