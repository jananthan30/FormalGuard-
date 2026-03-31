# Vulnerable AES-256 Reference Design

## Intentional Vulnerability: Timing Side-Channel

This design contains a **deliberate** security vulnerability for demonstrating FormalGuard's detection capabilities.

### The Bug

The implementation checks whether the key contains any zero-valued bytes. If it does, the design **skips rounds** (executes only 8 instead of 14), completing the operation faster. This is a simplified model of a real-world timing side-channel where data-dependent optimizations leak information about secret values.

```systemverilog
// BUG: Keys with zero bytes get fewer rounds
logic [3:0] effective_rounds;
assign effective_rounds = key_has_zero_bytes ? 4'd8 : 4'd14;
```

### What This Demonstrates

An attacker measuring encryption time can determine whether the key contains zero bytes — a significant information leak that narrows the key search space.

### FormalGuard Detection Results

| Property | Expected Result | Why |
|----------|----------------|-----|
| FG_AES_FUNC_001 | **PASS** | Operations still complete within max latency |
| FG_AES_FUNC_004 | **PASS** | Key length enforcement is unaffected |
| FG_AES_TIME_001 | **FAIL** | Detects key-dependent timing variation |
| FG_AES_TIME_003 | **FAIL** | Detects early termination (8 < 14 minimum rounds) |

This shows that **functional correctness alone is insufficient** — timing properties are essential for security verification.

### Running Verification

```bash
cd reference_designs/vuln_aes
sby -f vuln_aes.sby
# Expected: FAIL on timing properties, PASS on functional properties
```
