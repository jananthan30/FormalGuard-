// ============================================================================
// Vulnerable AES — Top-Level Wrapper for Formal Verification
// ============================================================================

module vuln_aes_top (
  input  logic         clk,
  input  logic         rst_n,
  input  logic         start,
  input  logic         encrypt,
  input  logic [255:0] key,
  input  logic [127:0] plaintext,
  input  logic         key_valid,
  input  logic [8:0]   key_length,
  output logic         done,
  output logic         busy,
  output logic         error,
  output logic [127:0] ciphertext,
  output logic [127:0] round_key,
  output logic [3:0]   round_count,
  output logic [127:0] state_reg,
  output logic         internal_err
);

  vuln_aes u_dut (
    .clk          (clk),
    .rst_n        (rst_n),
    .start        (start),
    .encrypt      (encrypt),
    .done         (done),
    .busy         (busy),
    .error        (error),
    .key          (key),
    .plaintext    (plaintext),
    .key_valid    (key_valid),
    .key_length   (key_length),
    .ciphertext   (ciphertext),
    .round_key    (round_key),
    .round_count  (round_count),
    .state_reg    (state_reg),
    .internal_err (internal_err)
  );

`ifdef FORMAL
  initial assume (!rst_n);
  always @(posedge clk) assume (rst_n);
  always @(posedge clk) begin
    if (busy) assume (!start);
  end
  always @(posedge clk) begin
    if (key_valid) assume (key_length == 9'd256);
  end
`endif

endmodule : vuln_aes_top
