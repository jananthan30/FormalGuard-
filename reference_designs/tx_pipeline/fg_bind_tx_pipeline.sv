// ============================================================================
// FormalGuard — Binding Module for Transaction Pipeline Reference Design
// ============================================================================

module fg_bind_tx_pipeline;

  fg_tx_if fg_tx();

  assign fg_tx.clk              = tx_pipeline_top.clk;
  assign fg_tx.rst_n            = tx_pipeline_top.rst_n;
  assign fg_tx.tx_start         = tx_pipeline_top.tx_start;
  assign fg_tx.tx_commit        = tx_pipeline_top.tx_commit;
  assign fg_tx.tx_abort         = tx_pipeline_top.tx_abort;
  assign fg_tx.tx_active        = tx_pipeline_top.tx_active;
  assign fg_tx.tx_error         = tx_pipeline_top.tx_error;
  assign fg_tx.tx_id            = tx_pipeline_top.tx_id;
  assign fg_tx.prev_tx_id       = tx_pipeline_top.prev_tx_id;
  assign fg_tx.tx_data_in       = tx_pipeline_top.tx_data_in;
  assign fg_tx.tx_data_out      = tx_pipeline_top.tx_data_out;
  assign fg_tx.tx_checksum_in   = tx_pipeline_top.tx_checksum_in;
  assign fg_tx.tx_checksum_out  = tx_pipeline_top.tx_checksum_out;
  assign fg_tx.pipeline_stage   = tx_pipeline_top.pipeline_stage;
  assign fg_tx.pipeline_full    = tx_pipeline_top.pipeline_full;
  assign fg_tx.pipeline_empty   = tx_pipeline_top.pipeline_empty;
  assign fg_tx.pre_tx_state     = tx_pipeline_top.pre_tx_state;
  assign fg_tx.post_abort_state = tx_pipeline_top.post_abort_state;
  assign fg_tx.rollback_complete = tx_pipeline_top.rollback_complete;

  genvar i;
  generate
    for (i = 0; i < fg_pkg::FG_TX_PIPELINE_DEPTH; i++) begin : gen_stage
      assign fg_tx.stage_reg[i]   = tx_pipeline_top.stage_reg[i];
      assign fg_tx.stage_tx_id[i] = tx_pipeline_top.stage_tx_id[i];
    end
  endgenerate

  fg_tx_atomicity u_atom  (.tx(fg_tx.props));
  fg_tx_isolation u_isol  (.tx(fg_tx.props));
  fg_tx_integrity u_integ (.tx(fg_tx.props));
  fg_tx_ordering  u_order (.tx(fg_tx.props));

endmodule : fg_bind_tx_pipeline
