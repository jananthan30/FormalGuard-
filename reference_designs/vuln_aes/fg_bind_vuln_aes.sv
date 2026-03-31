// ============================================================================
// FormalGuard — Binding Module for Vulnerable AES Reference Design
// ============================================================================

module fg_bind_vuln_aes;

  fg_aes256_if fg_aes();

  assign fg_aes.clk          = vuln_aes_top.clk;
  assign fg_aes.rst_n        = vuln_aes_top.rst_n;
  assign fg_aes.start        = vuln_aes_top.start;
  assign fg_aes.done         = vuln_aes_top.done;
  assign fg_aes.busy         = vuln_aes_top.busy;
  assign fg_aes.encrypt      = vuln_aes_top.encrypt;
  assign fg_aes.error        = vuln_aes_top.error;
  assign fg_aes.key          = vuln_aes_top.key;
  assign fg_aes.plaintext    = vuln_aes_top.plaintext;
  assign fg_aes.ciphertext   = vuln_aes_top.ciphertext;
  assign fg_aes.key_valid    = vuln_aes_top.key_valid;
  assign fg_aes.key_length   = vuln_aes_top.key_length;
  assign fg_aes.round_key    = vuln_aes_top.round_key;
  assign fg_aes.round_count  = vuln_aes_top.round_count;
  assign fg_aes.state_reg    = vuln_aes_top.state_reg;
  assign fg_aes.internal_err = vuln_aes_top.internal_err;

  fg_aes_functional u_fg_func (
    .aes (fg_aes.props)
  );

  fg_aes_timing u_fg_timing (
    .aes (fg_aes.props)
  );

  fg_aes_fault u_fg_fault (
    .aes (fg_aes.props)
  );

endmodule : fg_bind_vuln_aes
