# AES-256 Verification Properties

## Overview

This directory contains FormalGuard SVA properties for verifying AES-256 cryptographic module implementations. The properties cover functional correctness, timing side-channel resistance, and fault injection detection.

## Property Summary

| File | Property ID | Description | Compliance |
|------|-------------|-------------|------------|
| `aes_functional.sv` | FG_AES_FUNC_001 | Operation completes within max latency | PCI-DSS 3.5.1 |
| `aes_functional.sv` | FG_AES_FUNC_002 | Encrypt-decrypt round-trip integrity | PCI-DSS 3.5.1 |
| `aes_functional.sv` | FG_AES_FUNC_003 | Key expansion matches FIPS 197 | FIPS 140-3 |
| `aes_functional.sv` | FG_AES_FUNC_004 | Reject keys shorter than 256 bits | PCI-DSS 3.6.1 |
| `aes_timing.sv` | FG_AES_TIME_001 | Key-independent constant time | PCI-DSS 3.5.1, FIPS 140-3 |
| `aes_timing.sv` | FG_AES_TIME_002 | Plaintext-independent constant time | PCI-DSS 3.5.1 |
| `aes_timing.sv` | FG_AES_TIME_003 | No early termination on special inputs | FIPS 140-3 |
| `aes_fault.sv` | FG_AES_FAULT_001 | Single-bit fault detection | FIPS 140-3 Level 3+ |
| `aes_fault.sv` | FG_AES_FAULT_002 | Error state on consistency failure | FIPS 140-3 |

## Interface Requirements

All properties bind through `fg_aes256_if` (defined in `interfaces/fg_aes256_if.sv`).

**Required signals:** `clk`, `rst_n`, `start`, `done`, `busy`, `encrypt`, `error`, `key`, `plaintext`, `ciphertext`, `key_valid`, `key_length`

**Optional signals (for deeper verification):** `round_key`, `round_count`, `state_reg`, `internal_err` — required for FG_AES_FUNC_003 and FG_AES_FAULT_001/002. Tie to 0 if your design does not expose internals.

## Tool Compatibility

| Tool | Status | Notes |
|------|--------|-------|
| SymbiYosys | Supported | Full property support via `sby` |
| Synopsys VC Formal | Supported | Primary development target |
| Cadence JasperGold | Supported | Standard SVA |
| Siemens OneSpin | Supported | Standard SVA |

## Usage

See `reference_designs/aes256_core/` for a complete binding example and `examples/aes256_basic/` for a step-by-step walkthrough.
