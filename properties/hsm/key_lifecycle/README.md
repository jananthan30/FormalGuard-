# HSM Key Lifecycle Verification Properties

## Overview

Properties for verifying the complete key lifecycle in Hardware Security Modules: generation, storage, rotation, and destruction (zeroization).

## Property Summary

| File | Property ID | Description | Compliance |
|------|-------------|-------------|------------|
| `key_generation.sv` | FG_HSM_KEY_001 | Generated keys meet minimum entropy/length | PCI-DSS 3.6.1 |
| `key_storage.sv` | FG_HSM_KEY_002 | Keys never appear on external bus | PCI-DSS 3.5.1 |
| `key_rotation.sv` | FG_HSM_KEY_004 | Key rotation is atomic | PCI-DSS 3.6.4 |
| `key_destruction.sv` | FG_HSM_KEY_003 | Zeroization completes within bounded time | FIPS 140-3, PCI-DSS 3.6.5 |
| `key_destruction.sv` | FG_HSM_KEY_005 | No key remnants after zeroization | FIPS 140-3 |

## Interface Requirements

All properties bind through `fg_hsm_if` (defined in `interfaces/fg_hsm_if.sv`).

Key observation signals required:
- `key_store[0:15]` — All key storage slots (for leak and zeroization checks)
- `ext_bus_data` — External bus data (for key leak detection)
- `ram_content` — RAM content (for post-zeroization verification)
