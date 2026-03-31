// ============================================================================
// FormalGuard — HSM Key Storage Properties
// ============================================================================
// Property ID:  FG_HSM_KEY_002
// Compliance:   PCI-DSS 3.5.1
//
// Verifies that key material never appears in plaintext on any
// external-facing bus. This is the most critical HSM property — if
// keys leak to an external bus, the entire security model collapses.
//
// Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
// SPDX-License-Identifier: Apache-2.0
// ============================================================================

module fg_hsm_key_storage (
  fg_hsm_if.props hsm
);

  import fg_pkg::*;

  // ==========================================================================
  // FG_HSM_KEY_002 — Key Never on External Bus
  // ==========================================================================
  // At no point during operation should any key stored in the HSM key store
  // appear on the external data bus. The external bus is the boundary between
  // the HSM security domain and the outside world.
  //
  // This property checks every key slot against the external bus data on
  // every clock cycle. If any match is found, it indicates a key leakage
  // vulnerability.
  //
  // Compliance: PCI-DSS 3.5.1
  // ==========================================================================

  // Check each key slot against the external bus
  genvar slot;
  generate
    for (slot = 0; slot < FG_HSM_KEY_SLOTS; slot++) begin : gen_key_leak_check

      property p_hsm_key_002_slot;
        @(posedge hsm.clk) disable iff (!hsm.rst_n)
        // If key slot is non-empty, its value must never appear on ext bus
        (hsm.key_store[slot] != '0)
        |-> (hsm.ext_bus_data != hsm.key_store[slot]);
      endproperty

      FG_HSM_KEY_002_SLOT: assert property (p_hsm_key_002_slot)
        else $error("FG_HSM_KEY_002 FAIL: Key from slot %0d found on external bus — key leakage!", slot);

    end
  endgenerate

  // Also check that partial key matches don't leak (upper/lower 128 bits)
  generate
    for (slot = 0; slot < FG_HSM_KEY_SLOTS; slot++) begin : gen_partial_leak

      property p_hsm_key_002_partial_hi;
        @(posedge hsm.clk) disable iff (!hsm.rst_n)
        (hsm.key_store[slot] != '0 && hsm.ext_bus_data != '0)
        |-> (hsm.ext_bus_data[255:128] != hsm.key_store[slot][255:128]);
      endproperty

      property p_hsm_key_002_partial_lo;
        @(posedge hsm.clk) disable iff (!hsm.rst_n)
        (hsm.key_store[slot] != '0 && hsm.ext_bus_data != '0)
        |-> (hsm.ext_bus_data[127:0] != hsm.key_store[slot][127:0]);
      endproperty

      FG_HSM_KEY_002_HI: assert property (p_hsm_key_002_partial_hi)
        else $error("FG_HSM_KEY_002 FAIL: Upper key half from slot %0d on external bus", slot);

      FG_HSM_KEY_002_LO: assert property (p_hsm_key_002_partial_lo)
        else $error("FG_HSM_KEY_002 FAIL: Lower key half from slot %0d on external bus", slot);

    end
  endgenerate

  // ==========================================================================
  // Coverage
  // ==========================================================================

  cover property (@(posedge hsm.clk) hsm.ext_bus_data != '0);

endmodule : fg_hsm_key_storage
