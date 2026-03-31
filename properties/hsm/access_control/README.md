# HSM Access Control Verification Properties

## Property Summary

| File | Property ID | Description | Compliance |
|------|-------------|-------------|------------|
| `auth_enforcement.sv` | FG_HSM_AUTH_001 | No crypto operations without authentication | PCI-DSS 3.5.2 |
| `auth_enforcement.sv` | FG_HSM_AUTH_002 | Dual-control for critical operations | PCI-DSS 3.6.6 |
| `auth_enforcement.sv` | FG_HSM_AUTH_003 | Lockout after N failed auth attempts | PCI-DSS 8.1.6 |

## Interface Requirements

Binds through `fg_hsm_if`. Key signals:
- `auth_req/granted/failed` — Authentication lifecycle
- `fail_count`, `locked` — Lockout mechanism
- `dual_auth_req/granted`, `dual_control_active` — Dual-control enforcement
- `crypto_op_req/done/valid` — Cryptographic operation tracking
