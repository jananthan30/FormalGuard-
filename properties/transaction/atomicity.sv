// ============================================================================
// FormalGuard — Transaction Atomicity Properties
// ============================================================================
// Property ID:  FG_TX_ATOM_001
// Compliance:   SOX 404
//
// Verifies that transactions either complete fully (commit) or revert
// completely to the pre-transaction state (abort). No partial transactions.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module fg_tx_atomicity (
  fg_tx_if.props tx
);

  import fg_pkg::*;

  // ==========================================================================
  // FG_TX_ATOM_001 — All-or-Nothing Transaction Guarantee
  // ==========================================================================
  // A transaction must either:
  //   (a) Complete fully — tx_commit asserted with valid output, OR
  //   (b) Revert completely — tx_abort asserted and state returns to
  //       pre-transaction snapshot
  //
  // There must be no state where a transaction is partially applied.
  //
  // Compliance: SOX 404
  // ==========================================================================

  // Track transaction lifecycle
  logic tx_in_flight;
  logic [255:0] saved_pre_state;

  always_ff @(posedge tx.clk or negedge tx.rst_n) begin
    if (!tx.rst_n) begin
      tx_in_flight   <= 1'b0;
      saved_pre_state <= '0;
    end else begin
      if (tx.tx_start && !tx_in_flight) begin
        tx_in_flight    <= 1'b1;
        saved_pre_state <= tx.pre_tx_state;
      end
      if (tx.tx_commit || tx.tx_abort) begin
        tx_in_flight <= 1'b0;
      end
    end
  end

  // Every started transaction must eventually commit or abort
  property p_tx_atom_001_resolution;
    @(posedge tx.clk) disable iff (!tx.rst_n)
    (tx.tx_start && !tx_in_flight)
    |-> ##[1:FG_TX_MAX_LATENCY] (tx.tx_commit || tx.tx_abort);
  endproperty

  FG_TX_ATOM_001: assert property (p_tx_atom_001_resolution)
    else $error("FG_TX_ATOM_001 FAIL: Transaction did not commit or abort within %0d cycles",
                FG_TX_MAX_LATENCY);

  // On abort, state must revert to pre-transaction snapshot
  property p_tx_atom_001_revert;
    @(posedge tx.clk) disable iff (!tx.rst_n)
    (tx.tx_abort && tx_in_flight)
    |-> ##[0:3] (tx.rollback_complete && tx.post_abort_state == saved_pre_state);
  endproperty

  FG_TX_ATOM_001_REV: assert property (p_tx_atom_001_revert)
    else $error("FG_TX_ATOM_001 FAIL: Abort did not revert to pre-transaction state — partial transaction");

  // Commit and abort are mutually exclusive
  property p_tx_atom_001_exclusive;
    @(posedge tx.clk) disable iff (!tx.rst_n)
    !(tx.tx_commit && tx.tx_abort);
  endproperty

  FG_TX_ATOM_001_EXCL: assert property (p_tx_atom_001_exclusive)
    else $error("FG_TX_ATOM_001 FAIL: Commit and abort asserted simultaneously");

  // ==========================================================================
  // Coverage
  // ==========================================================================

  cover property (@(posedge tx.clk) tx.tx_start && !tx_in_flight);
  cover property (@(posedge tx.clk) tx.tx_commit && tx_in_flight);
  cover property (@(posedge tx.clk) tx.tx_abort && tx_in_flight);

endmodule : fg_tx_atomicity
