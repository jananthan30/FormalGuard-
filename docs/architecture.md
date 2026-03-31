# FormalGuard Architecture

## Five-Layer Architecture

```
+-----------------------------------------------------------+
|                   Compliance Reports                       |
|          (Human-readable, auditor-friendly HTML)           |
+-----------------------------------------------------------+
|                Compliance Mapping Engine                    |
|      (YAML-based property -> requirement mapping)          |
+-----------------------------------------------------------+
|               SVA Property Libraries                        |
|   +----------+----------+----------+----------+            |
|   |  Crypto  |   HSM    | Transact | Side-Ch  |            |
|   +----------+----------+----------+----------+            |
+-----------------------------------------------------------+
|               Property Binding Layer                        |
|        (Standardized interfaces for target designs)        |
+-----------------------------------------------------------+
|            Target Hardware Design (RTL)                     |
|      (User's design -- not part of FormalGuard)            |
+-----------------------------------------------------------+
```

## Design Principles

### Properties, Not Tools
FormalGuard is tool-agnostic. All properties use IEEE 1800-2017 standard SVA. No vendor extensions in the core library.

### Compliance-First
Every property traces to a regulatory requirement. If a property can't be mapped to a compliance standard, it doesn't belong in the core library.

### Minimal Assumptions
Properties bind through well-defined interfaces and assume nothing about implementation architecture — only observable port-level and state-level behavior.

### Auditable by Design
The compliance mapping engine produces reports that auditors can review without understanding SystemVerilog.

## Binding Model

Properties never embed inside user RTL. They connect through standardized SystemVerilog interfaces:

```
User's AES Design  <-->  fg_aes256_if  <-->  FormalGuard Properties
                         (binding layer)
```

The user writes a thin binding module connecting their signal names to the interface. This keeps properties portable across any implementation.

## Directory Structure

- `interfaces/` — Binding interfaces and shared package (the foundation everything depends on)
- `properties/` — SVA property libraries organized by domain
- `compliance/` — YAML regulatory mappings
- `reference_designs/` — Known-good and intentionally vulnerable RTL for testing
- `tools/` — Python tooling for report generation, linting, dashboards
- `examples/` — Worked verification examples
- `docs/` — Documentation
- `tests/` — CI tests for YAML validation and property correctness
