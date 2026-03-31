# HSM Tamper Response Verification Properties

## Property Summary

| File | Property ID | Description | Compliance |
|------|-------------|-------------|------------|
| `tamper_detect.sv` | FG_HSM_TAMP_001 | Tamper triggers zeroization within bounded cycles | FIPS 140-3 Level 3+ |
| `tamper_zeroize.sv` | FG_HSM_TAMP_002 | Zeroization is non-interruptible once initiated | FIPS 140-3 |
| `tamper_zeroize.sv` | FG_HSM_TAMP_003 | Post-tamper state has no key remnants (all slots zeroed) | FIPS 140-3 |

## Interface Requirements

Binds through `fg_hsm_if`. Key signals:
- `tamper_detect` — Physical tamper sensor input
- `zeroize_active`, `zeroize_done` — Zeroization lifecycle
- `key_store[0:15]` — All key slots (verified to be zero post-tamper)
- `ram_content` — RAM observation (verified clean post-tamper)
- `state` — HSM state (must reach and remain in HSM_TAMPERED)
