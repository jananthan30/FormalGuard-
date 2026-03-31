# Compliance Mapping Guide

## Overview

FormalGuard's compliance mapping engine connects formal verification properties to specific regulatory requirements. This creates an auditable trail from "property X was proven on design Y" to "requirement Z is satisfied."

## How It Works

1. **YAML Mappings**: Each compliance standard has a `mapping.yaml` file mapping requirement IDs to FormalGuard property IDs
2. **Verification Results**: Formal tools produce results (proven/failed) for each property
3. **Report Generator**: Crosses references mappings with results to produce coverage reports

## YAML Format

```yaml
standard: PCI-DSS
version: "4.0"
last_updated: "2026-03-30"

mappings:
  - requirement_id: "3.5.1"
    requirement_text: "Cryptographic keys are secured against disclosure"
    properties:
      - FG_AES_FUNC_001
      - FG_AES_TIME_001
    verification_status: null  # Populated by report generator
    notes: "Optional context for auditors"
```

## Adding a New Standard

1. Create a directory under `compliance/` (e.g., `compliance/fca/`)
2. Create `mapping.yaml` following the schema in `compliance/schema.yaml`
3. Map requirements to existing FormalGuard property IDs
4. Add a `README.md` explaining scope and limitations
5. Update `tools/compliance_report.py` `STANDARD_DIR_MAP` with the new key

## Property ID Naming

All property IDs follow: `FG_{DOMAIN}_{CATEGORY}_{NNN}`

| Domain | Categories |
|--------|-----------|
| AES | FUNC, TIME, FAULT |
| RSA | FUNC, TIME |
| SHA | FUNC |
| ECDSA | FUNC, NONCE |
| HSM | KEY, AUTH, TAMP |
| TX | ATOM, ISOL, INTEG, ORDER |
| SC | CT, PWR, DIF |

## Supported Standards

| Standard | Directory | Status |
|----------|-----------|--------|
| PCI-DSS v4.0 | `compliance/pci_dss/` | Phase 1 (active) |
| SWIFT CSP | `compliance/swift_csp/` | Phase 2 (stub) |
| SOX Section 404 | `compliance/sox/` | Phase 2 (stub) |
| ISO 27001:2022 | `compliance/iso27001/` | Phase 3 (stub) |

## Limitations

- Mappings cover **hardware-level** controls only
- FormalGuard does not replace qualified security assessors
- Verification proves properties about the RTL model, not manufactured silicon
- Coverage gaps (requirements with no mapped properties) indicate areas needing additional property development
