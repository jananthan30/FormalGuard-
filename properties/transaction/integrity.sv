// ============================================================================
// FormalGuard — Transaction Integrity Properties
// ============================================================================
// Property ID:  FG_TX_INTEG_001
// Compliance:   SOX 404, PCI-DSS 3.5.1
//
// Verifies end-to-end data integrity: the checksum computed at pipeline
// exit must match the checksum computed at pipeline entry.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module fg_tx_integrity (
  fg_tx_if.props tx
);

  import fg_pkg::*;

  // ==========================================================================
  // FG_TX_INTEG_001 — End-to-End Checksum Integrity
  // ==========================================================================
  // The data checksum at pipeline exit must match the checksum at pipeline
  // entry. If they differ, the transaction data was corrupted during
  // processing — a critical failure for financial transactions.
  //
  // Compliance: SOX 404, PCI-DSS 3.5.1
  // ==========================================================================

  // Capture entry checksum when transaction starts
  logic [31:0] entry_checksum;
  logic        checksum_captured;

  always_ff @(posedge tx.clk or negedge tx.rst_n) begin
    if (!tx.rst_n) begin
      entry_checksum   <= '0;
      checksum_captured <= 1'b0;
    end else begin
      if (tx.tx_start) begin
        entry_checksum   <= tx.tx_checksum_in;
        checksum_captured <= 1'b1;
      end
      if (tx.tx_commit || tx.tx_abort) begin
        checksum_captured <= 1'b0;
      end
    end
  end

  property p_tx_integ_001;
    @(posedge tx.clk) disable iff (!tx.rst_n)
    (tx.tx_commit && checksum_captured && !tx.tx_error)
    |-> (tx.tx_checksum_out == entry_checksum);
  endproperty

  FG_TX_INTEG_001: assert property (p_tx_integ_001)
    else $error("FG_TX_INTEG_001 FAIL: Exit checksum (0x%08h) != entry checksum (0x%08h) — data corrupted",
                tx.tx_checksum_out, entry_checksum);

  // Data at output should not be all-zeros if input was non-zero (sanity)
  property p_tx_integ_001_nonzero;
    @(posedge tx.clk) disable iff (!tx.rst_n)
    (tx.tx_commit && !tx.tx_error && tx.tx_data_in != '0)
    |-> (tx.tx_data_out != '0);
  endproperty

  FG_TX_INTEG_001_NZ: assert property (p_tx_integ_001_nonzero)
    else $error("FG_TX_INTEG_001 FAIL: Non-zero input produced all-zero output — data lost");

  // ==========================================================================
  // Coverage
  // ==========================================================================

  cover property (@(posedge tx.clk) tx.tx_commit && checksum_captured);
  cover property (@(posedge tx.clk) tx.tx_commit && tx.tx_checksum_out == entry_checksum);

endmodule : fg_tx_integrity
