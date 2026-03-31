# FIPS 140-3 Compliance Mapping

## Scope

Maps FormalGuard properties to FIPS 140-3 (Cryptographic Module Security Requirements) across areas relevant to RTL-level formal verification.

## Coverage

| Requirement | Description | Properties | Security Level |
|-------------|-------------|-----------|---------------|
| AS.03.10 | Approved algorithms | 7 | Level 1+ |
| AS.03.17 | Key management | 8 | Level 1+ |
| AS.04.31 | Physical security — tamper response | 5 | Level 3+ |
| AS.11.34 | Non-invasive attack mitigation | 8 | Level 3+ |
| AS.05.13 | Self-tests | 2 | Level 1+ |
| AS.10.45 | Authentication mechanisms | 3 | Level 2+ |

## Limitations

FIPS 140-3 certification requires testing by a CMVP-accredited lab. FormalGuard provides formal evidence supporting the verification process but does not constitute certification.
