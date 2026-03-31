# SHA-256 Verification Properties

## Property Summary

| File | Property ID | Description | Compliance |
|------|-------------|-------------|------------|
| `sha_functional.sv` | FG_SHA_FUNC_001 | Output matches NIST test vectors | FIPS 180-4 |
| `sha_functional.sv` | FG_SHA_FUNC_002 | Identical inputs produce identical outputs (determinism) | PCI-DSS 3.5.1 |
| `sha_functional.sv` | FG_SHA_FUNC_003 | Padding conforms to Merkle-Damgard standard | FIPS 180-4 |
| `sha_collision.sv` | (supplementary) | State reset between operations, no early digest | — |

## Interface Requirements

Binds through `fg_sha256_if` (defined in `interfaces/fg_sha256_if.sv`).

Key signals: `block_data`, `digest`, `digest_valid`, `msg_length`, `round_count`
