// ============================================================================
// Vulnerable HSM — Top-Level Wrapper for Formal Verification
// ============================================================================

module vuln_hsm_top
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

  vuln_hsm u_dut (.*);

`ifdef FORMAL
  initial assume (!rst_n);
  always @(posedge clk) assume (rst_n);
  always @(posedge clk) begin
    assume ($onehot0({key_gen_req, key_destroy_req, key_rotate_req,
                       crypto_op_req, auth_req, zeroize_cmd}));
  end
`endif

endmodule : vuln_hsm_top
