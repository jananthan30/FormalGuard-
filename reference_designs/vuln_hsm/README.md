# Vulnerable HSM Reference Design

## Intentional Vulnerability: Incomplete Zeroization

This design contains **two deliberate** security vulnerabilities:

### Bug 1: Wrong Slot Zeroed on Key Destruction
When a specific key slot is targeted for destruction, the design always zeroes slot 0 instead of the requested slot.

```systemverilog
// BUG: Always zeroes slot 0 instead of destroy_target
key_store[0] <= '0;  // Should be key_store[destroy_target]
```

### Bug 2: Partial Zeroization on Tamper
On tamper-triggered zeroization, only key slots 0-7 are cleared. Slots 8-15 retain their key material.

```systemverilog
// BUG: Only zeroes first half of key store
if (zeroize_counter < 4'd8) begin
  key_store[zeroize_counter] <= '0;
end
// Slots 8-15 are never touched
```

## FormalGuard Detection Results

| Property | Expected | Why |
|----------|----------|-----|
| FG_HSM_KEY_001 | **PASS** | Key generation works correctly |
| FG_HSM_KEY_003 | **PASS** | Zeroization completes in time (just incompletely) |
| FG_HSM_KEY_005 | **FAIL** | Target slot not actually zeroed |
| FG_HSM_TAMP_001 | **PASS** | Tamper triggers zeroization promptly |
| FG_HSM_TAMP_003 | **FAIL** | Slots 8-15 retain key material after tamper |

## Running Verification

```bash
sby -f vuln_hsm.sby
# Expected: FAIL on zeroization completeness properties
```
