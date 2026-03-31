// ============================================================================
// FormalGuard — Transaction Ordering Properties
// ============================================================================
// Property ID:  FG_TX_ORDER_001
// Compliance:   SWIFT CSP
//
// Verifies that transactions with sequential IDs commit in order.
// No reordering of financial transactions is permitted.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module fg_tx_ordering (
  fg_tx_if.props tx
);

  import fg_pkg::*;

  // ==========================================================================
  // FG_TX_ORDER_001 — Sequential Commit Ordering
  // ==========================================================================
  // Transactions must commit in the order they were submitted. If tx A
  // has a lower ID than tx B, then A must commit before B. This prevents
  // reordering attacks that could exploit race conditions in financial
  // settlement systems.
  //
  // Compliance: SWIFT CSP
  // ==========================================================================

  // Track the last committed transaction ID
  logic [31:0] last_committed_id;
  logic        has_committed;

  always_ff @(posedge tx.clk or negedge tx.rst_n) begin
    if (!tx.rst_n) begin
      last_committed_id <= '0;
      has_committed     <= 1'b0;
    end else begin
      if (tx.tx_commit) begin
        last_committed_id <= tx.tx_id;
        has_committed     <= 1'b1;
      end
    end
  end

  // Each committed tx must have a higher ID than the previous one
  property p_tx_order_001;
    @(posedge tx.clk) disable iff (!tx.rst_n)
    (tx.tx_commit && has_committed)
    |-> (tx.tx_id > last_committed_id);
  endproperty

  FG_TX_ORDER_001: assert property (p_tx_order_001)
    else $error("FG_TX_ORDER_001 FAIL: Transaction %0h committed after %0h — out-of-order commit",
                tx.tx_id, last_committed_id);

  // The prev_tx_id output must match our tracking
  property p_tx_order_001_tracking;
    @(posedge tx.clk) disable iff (!tx.rst_n)
    (tx.tx_commit && has_committed)
    |-> (tx.prev_tx_id == last_committed_id);
  endproperty

  FG_TX_ORDER_001_TRK: assert property (p_tx_order_001_tracking)
    else $error("FG_TX_ORDER_001 FAIL: prev_tx_id mismatch — pipeline lost track of ordering");

  // ==========================================================================
  // Coverage
  // ==========================================================================

  cover property (@(posedge tx.clk) tx.tx_commit && has_committed);
  cover property (@(posedge tx.clk) tx.tx_commit && tx.tx_id == last_committed_id + 32'd1);

endmodule : fg_tx_ordering
