# Transaction Pipeline Verification Properties

## Property Summary

| File | Property ID | Description | Compliance |
|------|-------------|-------------|------------|
| `atomicity.sv` | FG_TX_ATOM_001 | Transaction completes fully or reverts (all-or-nothing) | SOX 404 |
| `isolation.sv` | FG_TX_ISOL_001 | No cross-transaction data leakage in pipeline | PCI-DSS 3.4 |
| `integrity.sv` | FG_TX_INTEG_001 | Exit checksum matches entry checksum | SOX 404, PCI-DSS 3.5.1 |
| `ordering.sv` | FG_TX_ORDER_001 | Sequential transactions commit in order | SWIFT CSP |

## Interface Requirements

Binds through `fg_tx_if` (defined in `interfaces/fg_tx_if.sv`).

Key signals:
- `tx_start/commit/abort` — Transaction lifecycle
- `tx_data_in/out`, `tx_checksum_in/out` — Data and integrity
- `stage_reg[0:3]`, `stage_tx_id[0:3]` — Pipeline isolation observation
- `pre_tx_state`, `post_abort_state`, `rollback_complete` — Atomicity verification
- `tx_id`, `prev_tx_id` — Ordering enforcement
