# PCI-DSS v4.0 Compliance Mapping

## Scope

This mapping covers PCI-DSS v4.0 requirements that apply to **hardware-level** cryptographic controls. It focuses on Requirements 3 (Protect Stored Account Data), 4 (Protect Cardholder Data During Transmission), and 8 (Identify Users and Authenticate Access).

## Coverage

| Requirement | Description | Properties | Phase |
|-------------|-------------|-----------|-------|
| 3.5.1 | Key security against disclosure | 9 properties | 1-3 |
| 3.5.2 | Auth before crypto operations | 1 property | 2 |
| 3.6.1 | Strong key management | 3 properties | 1-2 |
| 3.6.4 | Key rotation | 1 property | 2 |
| 3.6.5 | Key retirement/destruction | 2 properties | 2 |
| 3.6.6 | Dual control | 1 property | 2 |
| 3.4 | Data access restriction | 1 property | 3 |
| 8.1.6 | Failed auth lockout | 1 property | 2 |

## Limitations

- This mapping covers hardware controls only. Software and process controls must be verified separately.
- FormalGuard does not replace a Qualified Security Assessor (QSA). It provides formal evidence to support PCI-DSS audits.
- Verification proves properties about the RTL model, not about manufactured silicon.
