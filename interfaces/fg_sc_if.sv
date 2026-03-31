// ============================================================================
// FormalGuard — Side-Channel Resistance Binding Interface
// ============================================================================
// Standardized interface for binding FormalGuard side-channel resistance
// verification properties to cryptographic implementations.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

interface fg_sc_if;

  import fg_pkg::*;

  // Clock and Reset
  logic         clk;
  logic         rst_n;

  // ---- Operation Lifecycle ----
  logic         op_start;
  logic         op_done;
  logic         op_busy;

  // ---- Secret Data ----
  logic [255:0] secret_data;     // Key or other secret input
  logic [255:0] public_data;     // Non-secret input (plaintext, message)

  // ---- Execution Path Observation ----
  logic [31:0]  cycle_count;     // Cycles from start to done
  logic [15:0]  branch_trace;    // Encoding of conditional branches taken
  logic [15:0]  branch_count;    // Total number of branches executed

  // ---- Power Analysis Observation ----
  logic [31:0]  hamming_weight;  // Hamming weight of intermediate registers
  logic [127:0] intermediate_reg; // Key-dependent intermediate value

  // ---- Control Flow ----
  logic [7:0]   pc_trace;        // Program counter / FSM state trace
  logic         data_dependent_branch; // Asserted if a branch depends on secret

  // Clocking Block
  clocking cb @(posedge clk);
    input rst_n;
    input op_start, op_done, op_busy;
    input secret_data, public_data;
    input cycle_count, branch_trace, branch_count;
    input hamming_weight, intermediate_reg;
    input pc_trace, data_dependent_branch;
  endclocking

  modport props (
    input  clk, rst_n,
    input  op_start, op_done, op_busy,
    input  secret_data, public_data,
    input  cycle_count, branch_trace, branch_count,
    input  hamming_weight, intermediate_reg,
    input  pc_trace, data_dependent_branch,
    clocking cb
  );

  modport dut (
    input  clk, rst_n,
    input  op_start, secret_data, public_data,
    output op_done, op_busy,
    output cycle_count, branch_trace, branch_count,
    output hamming_weight, intermediate_reg,
    output pc_trace, data_dependent_branch
  );

endinterface : fg_sc_if
