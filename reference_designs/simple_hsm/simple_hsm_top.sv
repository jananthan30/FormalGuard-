// ============================================================================
// Simple HSM — Top-Level Wrapper for Formal Verification
// ============================================================================

module simple_hsm_top
  import fg_pkg::*;
(
  input  logic         clk,
  input  logic         rst_n,
  input  logic         key_gen_req,
  input  logic [3:0]   key_id,
  input  logic         key_destroy_req,
  input  logic         key_rotate_req,
  input  logic         auth_req,
  input  hsm_role_t    auth_role,
  input  logic         dual_auth_req,
  input  logic         crypto_op_req,
  input  logic         tamper_detect,
  input  logic         zeroize_cmd,
  output logic         key_gen_done,
  output logic [255:0] key_data,
  output logic [8:0]   key_length,
  output logic         key_valid,
  output logic         key_destroy_done,
  output logic         key_rotate_done,
  output logic         new_key_active,
  output logic         old_key_invalid,
  output logic         auth_granted,
  output logic         auth_failed,
  output logic [3:0]   fail_count,
  output logic         locked,
  output logic         dual_auth_granted,
  output logic         dual_control_active,
  output logic         crypto_op_done,
  output logic         crypto_op_valid,
  output logic         zeroize_active,
  output logic         zeroize_done,
  output logic [255:0] key_store [0:FG_HSM_KEY_SLOTS-1],
  output logic [255:0] ext_bus_data,
  output logic [255:0] ram_content,
  output hsm_state_t   state
);

  simple_hsm u_dut (
    .clk               (clk),
    .rst_n             (rst_n),
    .key_gen_req       (key_gen_req),
    .key_gen_done      (key_gen_done),
    .key_id            (key_id),
    .key_data          (key_data),
    .key_length        (key_length),
    .key_valid         (key_valid),
    .key_destroy_req   (key_destroy_req),
    .key_destroy_done  (key_destroy_done),
    .key_rotate_req    (key_rotate_req),
    .key_rotate_done   (key_rotate_done),
    .new_key_active    (new_key_active),
    .old_key_invalid   (old_key_invalid),
    .auth_req          (auth_req),
    .auth_granted      (auth_granted),
    .auth_failed       (auth_failed),
    .auth_role         (auth_role),
    .fail_count        (fail_count),
    .locked            (locked),
    .dual_auth_req     (dual_auth_req),
    .dual_auth_granted (dual_auth_granted),
    .dual_control_active(dual_control_active),
    .crypto_op_req     (crypto_op_req),
    .crypto_op_done    (crypto_op_done),
    .crypto_op_valid   (crypto_op_valid),
    .tamper_detect     (tamper_detect),
    .zeroize_active    (zeroize_active),
    .zeroize_done      (zeroize_done),
    .zeroize_cmd       (zeroize_cmd),
    .key_store         (key_store),
    .ext_bus_data      (ext_bus_data),
    .ram_content       (ram_content),
    .state             (state)
  );

`ifdef FORMAL
  initial assume (!rst_n);
  always @(posedge clk) assume (rst_n);

  // Don't issue multiple commands simultaneously
  always @(posedge clk) begin
    assume ($onehot0({key_gen_req, key_destroy_req, key_rotate_req,
                       crypto_op_req, auth_req, zeroize_cmd}));
  end
`endif

endmodule : simple_hsm_top
