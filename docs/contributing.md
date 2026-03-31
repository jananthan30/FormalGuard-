# Contributing to FormalGuard

We welcome contributions from both the hardware verification and financial security communities.

## Quality Criteria

Every property in the core library must satisfy all six criteria (from SPEC.md Section 8):

1. **Traceable** — Maps to at least one compliance requirement
2. **Testable** — Passes on at least one known-good reference design
3. **Falsifiable** — Fails on at least one known-bad (vulnerable) reference design
4. **Documented** — Has a README explaining intent, assumptions, and limitations
5. **Portable** — Uses only IEEE 1800-2017 standard SVA (no vendor extensions)
6. **Reviewed** — Approved by at least one domain expert

## How to Contribute

### New Properties
1. Identify the compliance requirement(s) the property addresses
2. Write the SVA property following the naming convention: `FG_{DOMAIN}_{CATEGORY}_{NNN}`
3. Add the property to the appropriate module in `properties/`
4. Verify it passes on the relevant reference design
5. Verify it fails on a vulnerable design (create one if needed)
6. Add the compliance mapping entry to the relevant YAML file
7. Update `docs/property-catalog.md`
8. Submit a PR with all artifacts

### New Compliance Mappings
1. Create a directory under `compliance/`
2. Write `mapping.yaml` following `compliance/schema.yaml`
3. Include a `README.md` explaining scope
4. Submit a PR

### Bug Fixes and Improvements
1. Fork the repo, create a branch
2. Make your changes
3. Ensure `make test` passes
4. Submit a PR with a clear description

## Naming Convention

Property IDs: `FG_{DOMAIN}_{CATEGORY}_{NNN}`
- Domain: AES, RSA, SHA, ECDSA, HSM, TX, SC
- Category: FUNC, TIME, FAULT, KEY, AUTH, TAMP, ATOM, ISOL, INTEG, ORDER, CT, PWR, DIF, NONCE
- NNN: Three-digit sequential number within domain+category

## Priority Areas

- Post-quantum cryptography properties (Kyber, Dilithium)
- Additional compliance mappings (FINMA, MAS, FCA)
- Reference designs for common financial hardware
- Integration guides for open-source tools (SymbiYosys, EBMC)
- Threat model documentation for specific attack surfaces
