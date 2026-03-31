// ============================================================================
// Transaction Pipeline — Top-Level Wrapper for Formal Verification
// ============================================================================

module tx_pipeline_top
  import fg_pkg::*;
(
  input  logic         clk,
  input  logic         rst_n,
  input  logic         tx_start,
  input  logic [255:0] tx_data_in,
  output logic         tx_commit,
  output logic         tx_abort,
  output logic         tx_active,
  output logic         tx_error,
  output logic [31:0]  tx_id,
  output logic [31:0]  prev_tx_id,
  output logic [255:0] tx_data_out,
  output logic [31:0]  tx_checksum_in,
  output logic [31:0]  tx_checksum_out,
  output logic [3:0]   pipeline_stage,
  output logic         pipeline_full,
  output logic         pipeline_empty,
  output logic [255:0] stage_reg [0:FG_TX_PIPELINE_DEPTH-1],
  output logic [31:0]  stage_tx_id [0:FG_TX_PIPELINE_DEPTH-1],
  output logic [255:0] pre_tx_state,
  output logic [255:0] post_abort_state,
  output logic         rollback_complete
);

  tx_pipeline u_dut (.*);

`ifdef FORMAL
  initial assume (!rst_n);
  always @(posedge clk) assume (rst_n);

  // Don't start a new transaction while one is active
  always @(posedge clk) begin
    if (tx_active) assume (!tx_start);
  end
`endif

endmodule : tx_pipeline_top
