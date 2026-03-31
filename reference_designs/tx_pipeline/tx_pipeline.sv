// ============================================================================
// Transaction Pipeline — Known-Good Reference Implementation
// ============================================================================
// 4-stage pipeline for hardware-accelerated financial transaction processing.
// Implements atomicity, isolation, integrity (CRC checksum), and in-order
// commit guarantees.
//
// This is a REFERENCE DESIGN for testing FormalGuard properties.
// DO NOT use in production.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module tx_pipeline
  import fg_pkg::*;
(
  input  logic         clk,
  input  logic         rst_n,

  // Transaction input
  input  logic         tx_start,
  input  logic [255:0] tx_data_in,

  // Transaction output
  output logic         tx_commit,
  output logic         tx_abort,
  output logic         tx_active,
  output logic         tx_error,
  output logic [31:0]  tx_id,
  output logic [31:0]  prev_tx_id,
  output logic [255:0] tx_data_out,
  output logic [31:0]  tx_checksum_in,
  output logic [31:0]  tx_checksum_out,

  // Pipeline state
  output logic [3:0]   pipeline_stage,
  output logic         pipeline_full,
  output logic         pipeline_empty,

  // Observation
  output logic [255:0] stage_reg [0:FG_TX_PIPELINE_DEPTH-1],
  output logic [31:0]  stage_tx_id [0:FG_TX_PIPELINE_DEPTH-1],
  output logic [255:0] pre_tx_state,
  output logic [255:0] post_abort_state,
  output logic         rollback_complete
);

  // --------------------------------------------------------------------------
  // Internal State
  // --------------------------------------------------------------------------

  typedef enum logic [2:0] {
    PIPE_IDLE    = 3'b000,
    PIPE_STAGE1  = 3'b001,  // Validate and checksum
    PIPE_STAGE2  = 3'b010,  // Process
    PIPE_STAGE3  = 3'b011,  // Verify
    PIPE_STAGE4  = 3'b100,  // Commit or abort
    PIPE_CLEANUP = 3'b101
  } pipe_state_t;

  pipe_state_t state;

  logic [31:0]  next_tx_id;
  logic [31:0]  last_committed_id;
  logic [31:0]  current_checksum;
  logic [255:0] current_data;
  logic [255:0] snapshot;
  logic         has_committed;

  // --------------------------------------------------------------------------
  // CRC-32 checksum computation
  // --------------------------------------------------------------------------

  function automatic logic [31:0] compute_checksum(input logic [255:0] data);
    logic [31:0] crc;
    crc = 32'hFFFFFFFF;
    for (int i = 0; i < 32; i++) begin
      crc = fg_pkg::crc32_byte(crc, data[i*8 +: 8]);
    end
    return crc ^ 32'hFFFFFFFF;
  endfunction

  // --------------------------------------------------------------------------
  // FSM
  // --------------------------------------------------------------------------

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state              <= PIPE_IDLE;
      tx_commit          <= 1'b0;
      tx_abort           <= 1'b0;
      tx_active          <= 1'b0;
      tx_error           <= 1'b0;
      tx_id              <= '0;
      prev_tx_id         <= '0;
      tx_data_out        <= '0;
      tx_checksum_in     <= '0;
      tx_checksum_out    <= '0;
      pipeline_stage     <= '0;
      pipeline_full      <= 1'b0;
      pipeline_empty     <= 1'b1;
      pre_tx_state       <= '0;
      post_abort_state   <= '0;
      rollback_complete  <= 1'b0;
      next_tx_id         <= 32'd1;
      last_committed_id  <= '0;
      current_checksum   <= '0;
      current_data       <= '0;
      snapshot           <= '0;
      has_committed      <= 1'b0;

      for (int i = 0; i < FG_TX_PIPELINE_DEPTH; i++) begin
        stage_reg[i]   <= '0;
        stage_tx_id[i] <= '0;
      end

    end else begin
      // Clear single-cycle pulses
      tx_commit         <= 1'b0;
      tx_abort          <= 1'b0;
      tx_error          <= 1'b0;
      rollback_complete <= 1'b0;

      case (state)

        PIPE_IDLE: begin
          pipeline_empty <= 1'b1;
          pipeline_full  <= 1'b0;
          tx_active      <= 1'b0;

          if (tx_start) begin
            // Start new transaction
            state          <= PIPE_STAGE1;
            tx_active      <= 1'b1;
            tx_id          <= next_tx_id;
            current_data   <= tx_data_in;
            pipeline_empty <= 1'b0;
            pipeline_stage <= 4'd0;

            // Snapshot state for atomicity rollback
            snapshot       <= pre_tx_state;

            // Compute entry checksum
            tx_checksum_in <= compute_checksum(tx_data_in);
            current_checksum <= compute_checksum(tx_data_in);

            // Load stage 0
            stage_reg[0]   <= tx_data_in;
            stage_tx_id[0] <= next_tx_id;
          end
        end

        PIPE_STAGE1: begin
          // Stage 1: Validate transaction data
          pipeline_stage <= 4'd1;
          stage_reg[1]   <= current_data;
          stage_tx_id[1] <= tx_id;

          // Clear previous stage
          stage_reg[0]   <= '0;
          stage_tx_id[0] <= '0;

          state <= PIPE_STAGE2;
        end

        PIPE_STAGE2: begin
          // Stage 2: Process (pass-through for reference design)
          pipeline_stage <= 4'd2;
          stage_reg[2]   <= current_data;
          stage_tx_id[2] <= tx_id;

          // Clear previous stage
          stage_reg[1]   <= '0;
          stage_tx_id[1] <= '0;

          state <= PIPE_STAGE3;
        end

        PIPE_STAGE3: begin
          // Stage 3: Verify — recompute checksum on processed data
          pipeline_stage  <= 4'd3;
          tx_checksum_out <= compute_checksum(current_data);
          stage_reg[3]    <= current_data;
          stage_tx_id[3]  <= tx_id;

          // Clear previous stage
          stage_reg[2]   <= '0;
          stage_tx_id[2] <= '0;

          state <= PIPE_STAGE4;
        end

        PIPE_STAGE4: begin
          // Stage 4: Commit or abort based on checksum match
          if (tx_checksum_out == current_checksum) begin
            // Checksums match — commit
            tx_commit      <= 1'b1;
            tx_data_out    <= current_data;
            prev_tx_id     <= last_committed_id;
            last_committed_id <= tx_id;
            next_tx_id     <= next_tx_id + 32'd1;
            has_committed  <= 1'b1;
          end else begin
            // Checksum mismatch — abort and rollback
            tx_abort          <= 1'b1;
            tx_error          <= 1'b1;
            post_abort_state  <= snapshot;
            rollback_complete <= 1'b1;
          end

          state <= PIPE_CLEANUP;
        end

        PIPE_CLEANUP: begin
          // Clear all pipeline registers for isolation
          for (int i = 0; i < FG_TX_PIPELINE_DEPTH; i++) begin
            stage_reg[i]   <= '0;
            stage_tx_id[i] <= '0;
          end
          pipeline_empty <= 1'b1;
          tx_active      <= 1'b0;
          state          <= PIPE_IDLE;
        end

        default: begin
          state    <= PIPE_IDLE;
          tx_error <= 1'b1;
        end

      endcase
    end
  end

endmodule : tx_pipeline
