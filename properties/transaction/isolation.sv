// ============================================================================
// FormalGuard — Transaction Isolation Properties
// ============================================================================
// Property ID:  FG_TX_ISOL_001
// Compliance:   PCI-DSS 3.4
//
// Verifies that no data from one transaction is observable in another
// transaction's pipeline registers. Prevents cross-transaction data
// leakage in hardware-accelerated financial processing.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module fg_tx_isolation (
  fg_tx_if.props tx
);

  import fg_pkg::*;

  // ==========================================================================
  // FG_TX_ISOL_001 — No Cross-Transaction Data Leakage
  // ==========================================================================
  // Pipeline registers belonging to one transaction must not contain data
  // from a different transaction. Each pipeline stage has an associated
  // tx_id; the data in that stage must belong to that transaction only.
  //
  // This catches designs that fail to clear pipeline registers between
  // transactions, potentially leaking sensitive financial data.
  //
  // Compliance: PCI-DSS 3.4
  // ==========================================================================

  // Check that pipeline stages only contain data belonging to their tagged tx
  genvar stage;
  generate
    for (stage = 0; stage < FG_TX_PIPELINE_DEPTH; stage++) begin : gen_isol_check

      // When a stage is active (non-zero tx_id), its data must not match
      // data from a different transaction in an adjacent stage
      property p_tx_isol_001_stage;
        @(posedge tx.clk) disable iff (!tx.rst_n)
        // If this stage and the next stage hold different transactions
        (stage < FG_TX_PIPELINE_DEPTH - 1 &&
         tx.stage_tx_id[stage] != '0 &&
         tx.stage_tx_id[stage + 1] != '0 &&
         tx.stage_tx_id[stage] != tx.stage_tx_id[stage + 1])
        |->
        // Their data registers must be independent (not leaked)
        (tx.stage_reg[stage] != tx.stage_reg[stage + 1] ||
         tx.stage_reg[stage] == '0);
      endproperty

      FG_TX_ISOL_001_STG: assert property (p_tx_isol_001_stage)
        else $error("FG_TX_ISOL_001 FAIL: Data leakage between stage %0d (tx %0h) and stage %0d (tx %0h)",
                    stage, tx.stage_tx_id[stage], stage + 1, tx.stage_tx_id[stage + 1]);

    end
  endgenerate

  // After a transaction commits or aborts, its pipeline stages must be cleared
  property p_tx_isol_001_clear;
    @(posedge tx.clk) disable iff (!tx.rst_n)
    (tx.tx_commit || tx.tx_abort)
    |-> ##[1:FG_TX_PIPELINE_DEPTH] tx.pipeline_empty;
  endproperty

  FG_TX_ISOL_001: assert property (p_tx_isol_001_clear)
    else $error("FG_TX_ISOL_001 FAIL: Pipeline not cleared after transaction completion — stale data risk");

  // ==========================================================================
  // Coverage
  // ==========================================================================

  cover property (@(posedge tx.clk) !tx.pipeline_empty && tx.tx_active);
  cover property (@(posedge tx.clk) tx.tx_commit ##[1:4] tx.pipeline_empty);

endmodule : fg_tx_isolation
