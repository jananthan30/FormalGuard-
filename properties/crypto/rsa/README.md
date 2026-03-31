# RSA Verification Properties

## Property Summary

| File | Property ID | Description | Compliance |
|------|-------------|-------------|------------|
| `rsa_functional.sv` | FG_RSA_FUNC_001 | Signature round-trip (verify(sign(M)) succeeds) | PCI-DSS 3.5.1 |
| `rsa_functional.sv` | FG_RSA_FUNC_002 | Reject key lengths below 2048 bits | PCI-DSS 3.6.1 |
| `rsa_timing.sv` | FG_RSA_TIME_001 | Constant-time modular exponentiation | PCI-DSS 3.5.1 |

## Interface Requirements

Binds through `fg_rsa_if` (defined in `interfaces/fg_rsa_if.sv`).

Key signals: `modulus`, `exponent`, `message`, `result_data`, `mode_sign`, `key_length`
