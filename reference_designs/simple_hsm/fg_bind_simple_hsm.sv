// ============================================================================
// FormalGuard — Binding Module for Simple HSM Reference Design
// ============================================================================

module fg_bind_simple_hsm;

  fg_hsm_if fg_hsm();

  // Wire interface to DUT
  assign fg_hsm.clk                = simple_hsm_top.clk;
  assign fg_hsm.rst_n              = simple_hsm_top.rst_n;
  assign fg_hsm.state              = simple_hsm_top.state;
  assign fg_hsm.key_gen_req        = simple_hsm_top.key_gen_req;
  assign fg_hsm.key_gen_done       = simple_hsm_top.key_gen_done;
  assign fg_hsm.key_id             = simple_hsm_top.key_id;
  assign fg_hsm.key_data           = simple_hsm_top.key_data;
  assign fg_hsm.key_length         = simple_hsm_top.key_length;
  assign fg_hsm.key_valid          = simple_hsm_top.key_valid;
  assign fg_hsm.key_destroy_req    = simple_hsm_top.key_destroy_req;
  assign fg_hsm.key_destroy_done   = simple_hsm_top.key_destroy_done;
  assign fg_hsm.key_rotate_req     = simple_hsm_top.key_rotate_req;
  assign fg_hsm.key_rotate_done    = simple_hsm_top.key_rotate_done;
  assign fg_hsm.new_key_active     = simple_hsm_top.new_key_active;
  assign fg_hsm.old_key_invalid    = simple_hsm_top.old_key_invalid;
  assign fg_hsm.auth_req           = simple_hsm_top.auth_req;
  assign fg_hsm.auth_granted       = simple_hsm_top.auth_granted;
  assign fg_hsm.auth_failed        = simple_hsm_top.auth_failed;
  assign fg_hsm.auth_role          = simple_hsm_top.auth_role;
  assign fg_hsm.fail_count         = simple_hsm_top.fail_count;
  assign fg_hsm.locked             = simple_hsm_top.locked;
  assign fg_hsm.dual_auth_req      = simple_hsm_top.dual_auth_req;
  assign fg_hsm.dual_auth_granted  = simple_hsm_top.dual_auth_granted;
  assign fg_hsm.dual_control_active = simple_hsm_top.dual_control_active;
  assign fg_hsm.crypto_op_req      = simple_hsm_top.crypto_op_req;
  assign fg_hsm.crypto_op_done     = simple_hsm_top.crypto_op_done;
  assign fg_hsm.crypto_op_valid    = simple_hsm_top.crypto_op_valid;
  assign fg_hsm.tamper_detect      = simple_hsm_top.tamper_detect;
  assign fg_hsm.zeroize_active     = simple_hsm_top.zeroize_active;
  assign fg_hsm.zeroize_done       = simple_hsm_top.zeroize_done;
  assign fg_hsm.zeroize_cmd        = simple_hsm_top.zeroize_cmd;
  assign fg_hsm.ext_bus_data       = simple_hsm_top.ext_bus_data;
  assign fg_hsm.ram_content        = simple_hsm_top.ram_content;

  // Wire key_store array
  genvar i;
  generate
    for (i = 0; i < fg_pkg::FG_HSM_KEY_SLOTS; i++) begin : gen_ks
      assign fg_hsm.key_store[i] = simple_hsm_top.key_store[i];
    end
  endgenerate

  // Instantiate all HSM property modules
  fg_hsm_key_generation  u_key_gen   (.hsm(fg_hsm.props));
  fg_hsm_key_storage     u_key_store (.hsm(fg_hsm.props));
  fg_hsm_key_rotation    u_key_rot   (.hsm(fg_hsm.props));
  fg_hsm_key_destruction u_key_dest  (.hsm(fg_hsm.props));
  fg_hsm_auth_enforcement u_auth     (.hsm(fg_hsm.props));
  fg_hsm_tamper_detect   u_tamp_det  (.hsm(fg_hsm.props));
  fg_hsm_tamper_zeroize  u_tamp_zero (.hsm(fg_hsm.props));

endmodule : fg_bind_simple_hsm
