# Example: AES-256 Basic Verification

## Overview

This example demonstrates how to verify an AES-256 implementation using FormalGuard properties. It walks through binding, verification, and interpreting results.

## Prerequisites

- [SymbiYosys](https://symbiyosys.readthedocs.io/en/latest/install.html) (open-source formal verification)
- Or any commercial formal tool: Synopsys VC Formal, Cadence JasperGold, Siemens OneSpin

## Step-by-Step Walkthrough

### 1. Understand the Reference Design

The known-good AES-256 core is at `reference_designs/aes256_core/aes256_core.sv`. It's a textbook iterative implementation: 1 round per clock cycle, 14 rounds total, constant-time by design.

### 2. Examine the Binding

FormalGuard properties don't embed in your RTL. Instead, they bind through `fg_aes256_if`:

```
reference_designs/aes256_core/fg_bind_aes256_core.sv
```

This module:
1. Instantiates the `fg_aes256_if` interface
2. Wires the DUT's signals to the interface
3. Instantiates all three property modules: `fg_aes_functional`, `fg_aes_timing`, `fg_aes_fault`

### 3. Run Formal Verification

```bash
cd reference_designs/aes256_core
make verify
# Or directly:
sby -f aes256_core.sby
```

### 4. Expected Results (Known-Good Design)

All 9 properties should PROVE:
- FG_AES_FUNC_001: Operation completes within max latency
- FG_AES_FUNC_002: Round-trip integrity (encrypt then decrypt)
- FG_AES_FUNC_003: Key expansion matches FIPS 197
- FG_AES_FUNC_004: Rejects keys shorter than 256 bits
- FG_AES_TIME_001: Key-independent constant time
- FG_AES_TIME_002: Plaintext-independent constant time
- FG_AES_TIME_003: No early termination
- FG_AES_FAULT_001: Fault detection
- FG_AES_FAULT_002: Error state on consistency failure

### 5. Try the Vulnerable Design

```bash
cd reference_designs/vuln_aes
make verify
```

This design has an intentional timing side-channel. You should see:
- FG_AES_FUNC_* properties: **PASS**
- FG_AES_TIME_001: **FAIL** (key-dependent timing)
- FG_AES_TIME_003: **FAIL** (early termination)

This demonstrates that functional correctness alone is insufficient for security.

### 6. Adapting for Your Own Design

1. Copy `fg_bind_aes256_core.sv` as a starting point
2. Replace the hierarchical references with your design's signal names
3. Point the `.sby` file at your source files
4. Run `make verify`

See the [Property Catalog](../../docs/property-catalog.md) for the full list of available properties.
