// ============================================================================
// FormalGuard — Transaction Pipeline Binding Interface
// ============================================================================
// Standardized interface for binding FormalGuard transaction pipeline
// verification properties to any hardware-accelerated transaction
// processing implementation.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

interface fg_tx_if;

  import fg_pkg::*;

  // Clock and Reset
  logic         clk;
  logic         rst_n;

  // ---- Transaction Lifecycle ----
  logic         tx_start;           // New transaction enters pipeline
  logic         tx_commit;          // Transaction committed successfully
  logic         tx_abort;           // Transaction aborted / rolled back
  logic         tx_active;          // A transaction is in the pipeline
  logic         tx_error;           // Error during processing

  // ---- Transaction Identity ----
  logic [31:0]  tx_id;              // Unique transaction identifier
  logic [31:0]  prev_tx_id;         // ID of the most recently committed tx

  // ---- Data and Integrity ----
  logic [255:0] tx_data_in;         // Transaction data at pipeline entry
  logic [255:0] tx_data_out;        // Transaction data at pipeline exit
  logic [31:0]  tx_checksum_in;     // Checksum computed at entry
  logic [31:0]  tx_checksum_out;    // Checksum computed at exit

  // ---- Pipeline State ----
  logic [3:0]   pipeline_stage;     // Current stage (0 to FG_TX_PIPELINE_DEPTH-1)
  logic         pipeline_full;      // Pipeline cannot accept more transactions
  logic         pipeline_empty;     // No transactions in pipeline

  // ---- Isolation Observation ----
  // Signals for verifying cross-transaction data leakage
  logic [255:0] stage_reg [0:FG_TX_PIPELINE_DEPTH-1]; // Pipeline stage registers
  logic [31:0]  stage_tx_id [0:FG_TX_PIPELINE_DEPTH-1]; // Which tx owns each stage

  // ---- Rollback / Atomicity ----
  logic [255:0] pre_tx_state;       // State snapshot before transaction began
  logic [255:0] post_abort_state;   // State after abort completes
  logic         rollback_complete;  // Rollback to pre-tx state is done

  // Clocking Block
  clocking cb @(posedge clk);
    input rst_n;
    input tx_start, tx_commit, tx_abort, tx_active, tx_error;
    input tx_id, prev_tx_id;
    input tx_data_in, tx_data_out, tx_checksum_in, tx_checksum_out;
    input pipeline_stage, pipeline_full, pipeline_empty;
    input pre_tx_state, post_abort_state, rollback_complete;
  endclocking

  modport props (
    input  clk, rst_n,
    input  tx_start, tx_commit, tx_abort, tx_active, tx_error,
    input  tx_id, prev_tx_id,
    input  tx_data_in, tx_data_out, tx_checksum_in, tx_checksum_out,
    input  pipeline_stage, pipeline_full, pipeline_empty,
    input  stage_reg, stage_tx_id,
    input  pre_tx_state, post_abort_state, rollback_complete,
    clocking cb
  );

  modport dut (
    input  clk, rst_n,
    input  tx_start, tx_data_in,
    output tx_commit, tx_abort, tx_active, tx_error,
    output tx_id, prev_tx_id,
    output tx_data_out, tx_checksum_in, tx_checksum_out,
    output pipeline_stage, pipeline_full, pipeline_empty,
    output stage_reg, stage_tx_id,
    output pre_tx_state, post_abort_state, rollback_complete
  );

endinterface : fg_tx_if
