# Financial Hardware Threat Models

## Cryptographic Module Threats

### Timing Side-Channels
**Threat**: Attacker measures encryption/decryption time to infer secret key bits.
**Attack Vector**: Network timing, cache timing, EM emanation timing.
**FormalGuard Coverage**: FG_AES_TIME_001-003, FG_RSA_TIME_001, FG_SC_CT_001-002.
**Real-World Example**: Lucky Thirteen attack on CBC-mode TLS, Padding Oracle attacks.

### Fault Injection
**Threat**: Attacker induces computational faults (laser, voltage glitch, EM pulse) to corrupt intermediate cryptographic state, enabling Differential Fault Analysis (DFA).
**Attack Vector**: Physical access to the device.
**FormalGuard Coverage**: FG_AES_FAULT_001-002.
**Impact**: A single faulty ciphertext can reveal the full AES key in under an hour.

### Weak Key Generation
**Threat**: Insufficiently random keys reduce the effective key space.
**Attack Vector**: Faulty RNG, insufficient entropy sources, predictable seeding.
**FormalGuard Coverage**: FG_HSM_KEY_001, FG_AES_FUNC_004, FG_RSA_FUNC_002.
**Real-World Example**: Debian OpenSSL bug (CVE-2008-0166) — predictable keys due to RNG seeding error.

### ECDSA Nonce Reuse
**Threat**: Reusing the nonce `k` in two ECDSA signatures leaks the private key through simple algebra.
**Attack Vector**: Faulty RNG, deterministic nonce generation bugs.
**FormalGuard Coverage**: FG_ECDSA_NONCE_001-002.
**Real-World Example**: PlayStation 3 ECDSA key extraction (2010), Bitcoin wallet thefts.

## HSM Threats (Phase 2)

### Key Extraction via API Abuse
**Threat**: Manipulating the HSM command interface to export keys in cleartext or in a weak wrapping.
**FormalGuard Coverage**: FG_HSM_KEY_002 (key never on external bus), FG_HSM_AUTH_001-002 (access control).

### Incomplete Zeroization
**Threat**: Key material persists in RAM or registers after a key destruction command, allowing forensic recovery.
**FormalGuard Coverage**: FG_HSM_KEY_003, FG_HSM_KEY_005.
**Impact**: Violation of FIPS 140-3 Level 3+ requirements.

### Tamper Response Bypass
**Threat**: Disabling or bypassing physical tamper detection to access key material.
**FormalGuard Coverage**: FG_HSM_TAMP_001-003.

## Transaction Pipeline Threats (Phase 3)

### Cross-Transaction Data Leakage
**Threat**: Sensitive data from one transaction leaks into another through shared pipeline registers.
**FormalGuard Coverage**: FG_TX_ISOL_001.

### Transaction Reordering
**Threat**: Attacker manipulates transaction order to exploit race conditions in financial settlement.
**FormalGuard Coverage**: FG_TX_ORDER_001.

## Scope Limitations

FormalGuard addresses **RTL-level** threats that can be verified through formal methods on the hardware description. The following are out of scope:
- Analog side-channels (power analysis requires post-layout simulation)
- Supply chain attacks (physical tampering with manufactured chips)
- Software/firmware vulnerabilities above the hardware abstraction
- Social engineering and operational security failures
