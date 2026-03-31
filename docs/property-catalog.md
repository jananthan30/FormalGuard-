# FormalGuard Property Catalog

## AES-256 Cryptographic Module

### Functional Correctness (`properties/crypto/aes256/aes_functional.sv`)

| ID | Description | Compliance |
|----|-------------|------------|
| FG_AES_FUNC_001 | Operation completes within max latency when started with valid key | PCI-DSS 3.5.1 |
| FG_AES_FUNC_002 | Decrypt(Encrypt(P)) == P (round-trip integrity) | PCI-DSS 3.5.1 |
| FG_AES_FUNC_003 | Round 0 key matches FIPS 197 key schedule | FIPS 140-3 |
| FG_AES_FUNC_004 | Module rejects keys shorter than 256 bits | PCI-DSS 3.6.1 |

### Timing / Side-Channel Resistance (`properties/crypto/aes256/aes_timing.sv`)

| ID | Description | Compliance |
|----|-------------|------------|
| FG_AES_TIME_001 | Encryption latency is independent of key value | PCI-DSS 3.5.1, FIPS 140-3 |
| FG_AES_TIME_002 | Encryption latency is independent of plaintext value | PCI-DSS 3.5.1 |
| FG_AES_TIME_003 | No early termination (minimum latency enforced) | FIPS 140-3 |

### Fault Resistance (`properties/crypto/aes256/aes_fault.sv`)

| ID | Description | Compliance |
|----|-------------|------------|
| FG_AES_FAULT_001 | Single-bit state corruption detected (DFA resistance) | FIPS 140-3 Level 3+ |
| FG_AES_FAULT_002 | Internal consistency error triggers error state | FIPS 140-3 |

---

## RSA (Phase 2)

| ID | Description | Compliance |
|----|-------------|------------|
| FG_RSA_FUNC_001 | Signature verify(sign(M)) succeeds | PCI-DSS 3.5.1 |
| FG_RSA_FUNC_002 | Rejects key lengths below 2048 bits | PCI-DSS 3.6.1 |
| FG_RSA_TIME_001 | Modular exponentiation is constant-time | PCI-DSS 3.5.1 |

## SHA-256 (Phase 2)

| ID | Description | Compliance |
|----|-------------|------------|
| FG_SHA_FUNC_001 | Output matches NIST test vectors | FIPS 180-4 |
| FG_SHA_FUNC_002 | Identical inputs produce identical outputs | PCI-DSS 3.5.1 |
| FG_SHA_FUNC_003 | Padding conforms to Merkle-Damgard standard | FIPS 202 |

## ECDSA (Phase 3)

| ID | Description | Compliance |
|----|-------------|------------|
| FG_ECDSA_FUNC_001 | Sign-verify round-trip correctness | PCI-DSS 3.5.1 |
| FG_ECDSA_NONCE_001 | Nonce never repeats across signing operations | Critical |
| FG_ECDSA_NONCE_002 | Nonce uses approved DRBG, not static/predictable values | FIPS 186-5 |

---

## HSM Key Lifecycle (Phase 2)

| ID | Description | Compliance |
|----|-------------|------------|
| FG_HSM_KEY_001 | Generated keys meet minimum entropy requirements | PCI-DSS 3.6.1 |
| FG_HSM_KEY_002 | Keys never appear in plaintext on external bus | PCI-DSS 3.5.1 |
| FG_HSM_KEY_003 | Zeroization overwrites all copies within bounded time | FIPS 140-3, PCI-DSS 3.6.5 |
| FG_HSM_KEY_004 | Key rotation is atomic (old invalid only after new active) | PCI-DSS 3.6.4 |
| FG_HSM_KEY_005 | No key material persists in RAM after zeroization | FIPS 140-3 |

## HSM Access Control (Phase 2)

| ID | Description | Compliance |
|----|-------------|------------|
| FG_HSM_AUTH_001 | Crypto ops require prior authentication | PCI-DSS 3.5.2 |
| FG_HSM_AUTH_002 | Dual-control for critical operations | PCI-DSS 3.6.6 |
| FG_HSM_AUTH_003 | Lockout after N failed auth attempts | PCI-DSS 8.1.6 |

## HSM Tamper Response (Phase 2)

| ID | Description | Compliance |
|----|-------------|------------|
| FG_HSM_TAMP_001 | Tamper signal triggers zeroization within bounded cycles | FIPS 140-3 Level 3+ |
| FG_HSM_TAMP_002 | Zeroization is non-interruptible once initiated | FIPS 140-3 |
| FG_HSM_TAMP_003 | Post-tamper state has no key remnants | FIPS 140-3 |

---

## Transaction Pipeline (Phase 3)

| ID | Description | Compliance |
|----|-------------|------------|
| FG_TX_ATOM_001 | Transaction completes fully or reverts (atomicity) | SOX 404 |
| FG_TX_ISOL_001 | No cross-transaction data leakage (isolation) | PCI-DSS 3.4 |
| FG_TX_INTEG_001 | Checksum at exit matches checksum at entry (integrity) | SOX 404, PCI-DSS 3.5.1 |
| FG_TX_ORDER_001 | Sequential IDs commit in order (no reordering) | SWIFT CSP |

## Side-Channel Resistance (Phase 3)

| ID | Description | Compliance |
|----|-------------|------------|
| FG_SC_CT_001 | Execution path length independent of secret data | PCI-DSS 3.5.1, FIPS 140-3 |
| FG_SC_CT_002 | No conditional branches dependent on key material | FIPS 140-3 |
| FG_SC_PWR_001 | Register Hamming weight independent of key bits | FIPS 140-3 Level 3+ |
| FG_SC_DIF_001 | Control flow graph identical for all secret inputs | FIPS 140-3 |
