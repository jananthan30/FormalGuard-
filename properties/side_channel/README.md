# Side-Channel Resistance Verification Properties

## Property Summary

| File | Property ID | Description | Compliance |
|------|-------------|-------------|------------|
| `constant_time.sv` | FG_SC_CT_001 | Execution path length independent of secret data | PCI-DSS 3.5.1, FIPS 140-3 |
| `constant_time.sv` | FG_SC_CT_002 | No conditional branches dependent on key material | FIPS 140-3 |
| `power_balanced.sv` | FG_SC_PWR_001 | Intermediate register Hamming weight independent of key | FIPS 140-3 Level 3+ |
| `data_independent_flow.sv` | FG_SC_DIF_001 | Control flow graph identical for all secret inputs | FIPS 140-3 |

## Interface Requirements

Binds through `fg_sc_if` (defined in `interfaces/fg_sc_if.sv`).

Key observation signals:
- `cycle_count` — For constant-time verification
- `branch_trace`, `branch_count` — For control flow analysis
- `hamming_weight`, `intermediate_reg` — For power analysis resistance
- `pc_trace` — For control flow graph comparison
- `data_dependent_branch` — Flag from design indicating secret-dependent branch

## Design Integration Notes

Designs must expose observation signals for deep side-channel analysis. The `data_dependent_branch` signal should be tied high by the design whenever a conditional operation uses `secret_data` as input. If the design does not have explicit side-channel countermeasures, these properties will flag vulnerabilities.
