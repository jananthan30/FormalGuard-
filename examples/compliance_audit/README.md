# Example: PCI-DSS Compliance Audit Report

## Overview

This example shows how to generate a PCI-DSS compliance coverage report from formal verification results.

## Quick Start

```bash
# Generate a report from verification results
python tools/compliance_report.py \
  --standard pci-dss \
  --results examples/compliance_audit/sample_results.json \
  --output examples/compliance_audit/sample_report.html

# Or run a dry-run to see a text summary
python tools/compliance_report.py --standard pci-dss --dry-run
```

## Sample Results

The `sample_results.json` file contains example verification results showing a typical run where AES-256 properties have been verified but HSM properties have not yet been run.

## Interpreting the Report

The HTML report contains:

1. **Executive Summary** — Total requirements, proven count, failed count, coverage percentage
2. **Per-Requirement Breakdown** — Each PCI-DSS requirement with its mapped properties and verification status
3. **Color Coding**:
   - **Green (PROVEN)**: All mapped properties formally proven
   - **Red (FAILED)**: At least one property produced a counterexample
   - **Yellow (PARTIAL)**: Some properties proven, some not yet run
   - **Gray (NOT RUN)**: Properties mapped but not yet verified

## For Auditors

This report provides formal evidence that specific hardware security properties have been mathematically verified on the RTL model. It does not replace a qualified security assessment, but it provides rigorous evidence to support one.
