# FormalGuard — Technical Specification

**Version:** 0.1.0-draft  
**Authors:** Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy  
**Last Updated:** March 2026

---

## 1. Overview

FormalGuard is a formal verification framework that provides reusable SystemVerilog Assertion (SVA) libraries for verifying security properties in financial hardware. It bridges two domains that have historically operated in isolation: semiconductor formal verification and financial security compliance.

### 1.1 Design Philosophy

- **Properties, not tools.** FormalGuard is tool-agnostic. Properties are written in standard IEEE 1800 SystemVerilog and work with any compliant formal verification engine (Synopsys VC Formal, Cadence JasperGold, Siemens OneSpin, open-source SymbiYosys/EBMC).
- **Compliance-first.** Every property traces back to a specific regulatory requirement. If a property cannot be mapped to a compliance standard, it does not belong in the core library.
- **Minimal assumptions.** Properties bind to designs through well-defined interfaces. They assume nothing about implementation architecture — only observable port-level and state-level behavior.
- **Auditable by design.** The compliance mapping engine produces reports that auditors and compliance officers can review without understanding SystemVerilog.

### 1.2 Scope

**In scope:**
- SVA property libraries for cryptographic modules, HSMs, transaction pipelines, and side-channel resistance
- Compliance mappings to PCI-DSS, SWIFT CSP, SOX, ISO 27001, FIPS 140-3
- Reference designs for testing and demonstration
- Tooling for compliance report generation and property validation
- Documentation of financial hardware threat models

**Out of scope:**
- Building a formal verification engine (use existing tools)
- Full RTL implementations of production financial hardware
- Software-level security testing (application/API layer)
- Penetration testing or dynamic security analysis

---

## 2. Architecture

### 2.1 System Layers

```
┌─────────────────────────────────────────────────────────┐
│                  Compliance Reports                      │
│         (Human-readable, auditor-friendly)               │
├─────────────────────────────────────────────────────────┤
│               Compliance Mapping Engine                  │
│     (YAML-based property → requirement mapping)          │
├─────────────────────────────────────────────────────────┤
│              SVA Property Libraries                       │
│   ┌──────────┬──────────┬──────────┬──────────┐         │
│   │  Crypto  │   HSM    │ Transact │ Side-Ch  │         │
│   └──────────┴──────────┴──────────┴──────────┘         │
├─────────────────────────────────────────────────────────┤
│              Property Binding Layer                       │
│       (Interface adapters for target designs)            │
├─────────────────────────────────────────────────────────┤
│           Target Hardware Design (RTL)                    │
│     (User's design — not part of FormalGuard)            │
└─────────────────────────────────────────────────────────┘
```

### 2.2 Property Binding Model

FormalGuard properties do not directly instantiate inside a user's RTL. Instead, they bind through a standardized interface layer:

```systemverilog
// FormalGuard defines a standard interface for AES verification
interface fg_aes256_if;
  logic         clk;
  logic         rst_n;
  logic         start;
  logic         done;
  logic [255:0] key;
  logic [127:0] plaintext;
  logic [127:0] ciphertext;
  logic         key_valid;
  logic         busy;
endinterface

// User writes a thin binding module to connect their design
module fg_bind_my_aes (fg_aes256_if fg);
  assign fg.clk        = my_aes_top.clk;
  assign fg.rst_n      = my_aes_top.reset_n;
  assign fg.start      = my_aes_top.encrypt_start;
  assign fg.done       = my_aes_top.encrypt_done;
  assign fg.key        = my_aes_top.cipher_key;
  assign fg.plaintext  = my_aes_top.data_in;
  assign fg.ciphertext = my_aes_top.data_out;
  assign fg.key_valid  = my_aes_top.key_loaded;
  assign fg.busy       = my_aes_top.processing;
endmodule
```

This keeps FormalGuard properties portable across any AES implementation.

---

## 3. Property Library Specification

### 3.1 Cryptographic Module Properties

#### 3.1.1 AES-256

**Functional correctness properties:**

| Property ID | Description | Compliance Mapping |
|-------------|-------------|-------------------|
| `FG_AES_FUNC_001` | When `start` is asserted with valid key and plaintext, `ciphertext` must equal the AES-256 reference output within `N` cycles | PCI-DSS 3.5.1 |
| `FG_AES_FUNC_002` | Decryption of encrypted output must produce original plaintext (round-trip integrity) | PCI-DSS 3.5.1 |
| `FG_AES_FUNC_003` | Key expansion must produce correct round keys per FIPS 197 | FIPS 140-3 |
| `FG_AES_FUNC_004` | Module must not accept keys shorter than 256 bits | PCI-DSS 3.6.1 |

**Timing properties (side-channel resistance):**

| Property ID | Description | Compliance Mapping |
|-------------|-------------|-------------------|
| `FG_AES_TIME_001` | Encryption latency must be identical regardless of key value (constant-time) | PCI-DSS 3.5.1, FIPS 140-3 |
| `FG_AES_TIME_002` | Encryption latency must be identical regardless of plaintext value | PCI-DSS 3.5.1 |
| `FG_AES_TIME_003` | No early termination based on input patterns (zero-key, zero-plaintext) | FIPS 140-3 |

**Fault resistance properties:**

| Property ID | Description | Compliance Mapping |
|-------------|-------------|-------------------|
| `FG_AES_FAULT_001` | Single-bit flip in any round register must not produce valid ciphertext (fault detection) | FIPS 140-3 Level 3+ |
| `FG_AES_FAULT_002` | Module must enter error state if internal consistency check fails | FIPS 140-3 |

#### 3.1.2 RSA

| Property ID | Description | Compliance Mapping |
|-------------|-------------|-------------------|
| `FG_RSA_FUNC_001` | Signature verification of a signed message must succeed | PCI-DSS 3.5.1 |
| `FG_RSA_FUNC_002` | Module must reject key lengths below 2048 bits | PCI-DSS 3.6.1 |
| `FG_RSA_TIME_001` | Modular exponentiation must be constant-time (no timing leak of private key bits) | PCI-DSS 3.5.1 |

#### 3.1.3 SHA-256 / SHA-3

| Property ID | Description | Compliance Mapping |
|-------------|-------------|-------------------|
| `FG_SHA_FUNC_001` | Hash output must match NIST test vectors for known inputs | FIPS 180-4 |
| `FG_SHA_FUNC_002` | Identical inputs must always produce identical outputs (determinism) | PCI-DSS 3.5.1 |
| `FG_SHA_FUNC_003` | Padding must conform to standard (Merkle-Damgård for SHA-256, sponge for SHA-3) | FIPS 202 |

#### 3.1.4 ECDSA

| Property ID | Description | Compliance Mapping |
|-------------|-------------|-------------------|
| `FG_ECDSA_FUNC_001` | Signature generation and verification round-trip correctness | PCI-DSS 3.5.1 |
| `FG_ECDSA_NONCE_001` | Nonce `k` must never repeat across two signing operations (nonce reuse detection) | Critical — nonce reuse leaks private key |
| `FG_ECDSA_NONCE_002` | Nonce generation must use approved DRBG output, not static or predictable values | FIPS 186-5 |

### 3.2 HSM Properties

#### 3.2.1 Key Lifecycle Management

| Property ID | Description | Compliance Mapping |
|-------------|-------------|-------------------|
| `FG_HSM_KEY_001` | Generated keys must meet minimum entropy requirements | PCI-DSS 3.6.1 |
| `FG_HSM_KEY_002` | Keys must never appear in plaintext on any external-facing bus | PCI-DSS 3.5.1 |
| `FG_HSM_KEY_003` | Key destruction (zeroization) must overwrite all copies within bounded time | FIPS 140-3, PCI-DSS 3.6.5 |
| `FG_HSM_KEY_004` | Key rotation must complete atomically — old key invalid only after new key is confirmed active | PCI-DSS 3.6.4 |
| `FG_HSM_KEY_005` | No key material may persist in RAM after zeroization command completes | FIPS 140-3 |

#### 3.2.2 Access Control

| Property ID | Description | Compliance Mapping |
|-------------|-------------|-------------------|
| `FG_HSM_AUTH_001` | Cryptographic operations must not execute without prior authentication | PCI-DSS 3.5.2 |
| `FG_HSM_AUTH_002` | Dual-control: critical operations (key export, firmware update) require two independent authentications | PCI-DSS 3.6.6 |
| `FG_HSM_AUTH_003` | Failed authentication counter must increment and lock after N failures | PCI-DSS 8.1.6 |

#### 3.2.3 Tamper Response

| Property ID | Description | Compliance Mapping |
|-------------|-------------|-------------------|
| `FG_HSM_TAMP_001` | Tamper detection signal must trigger zeroization within bounded cycles | FIPS 140-3 Level 3+ |
| `FG_HSM_TAMP_002` | Zeroization must be non-interruptible once initiated | FIPS 140-3 |
| `FG_HSM_TAMP_003` | Post-tamper state must be non-recoverable (no key remnants) | FIPS 140-3 |

### 3.3 Transaction Pipeline Properties

| Property ID | Description | Compliance Mapping |
|-------------|-------------|-------------------|
| `FG_TX_ATOM_001` | A transaction either completes fully or reverts to pre-transaction state (atomicity) | SOX 404 |
| `FG_TX_ISOL_001` | No data from transaction A may be observable in transaction B's pipeline registers (isolation) | PCI-DSS 3.4 |
| `FG_TX_INTEG_001` | Transaction data checksum at pipeline exit must match checksum at pipeline entry | SOX 404, PCI-DSS 3.5.1 |
| `FG_TX_ORDER_001` | Transactions with sequential IDs must commit in order (no reordering) | SWIFT CSP |

### 3.4 Side-Channel Resistance Properties

| Property ID | Description | Compliance Mapping |
|-------------|-------------|-------------------|
| `FG_SC_CT_001` | Execution path length is independent of secret data values (constant-time) | PCI-DSS 3.5.1, FIPS 140-3 |
| `FG_SC_CT_002` | No conditional branches dependent on key material | FIPS 140-3 |
| `FG_SC_PWR_001` | Hamming weight of intermediate registers is independent of key bits (power-balanced) | FIPS 140-3 Level 3+ |
| `FG_SC_DIF_001` | Control flow graph is identical for all possible secret inputs | FIPS 140-3 |

---

## 4. Compliance Mapping Engine

### 4.1 Mapping Format

Compliance mappings are stored in YAML for readability and machine-parseability:

```yaml
# compliance/pci_dss/mapping.yaml
standard: PCI-DSS
version: "4.0"
mappings:
  - requirement_id: "3.5.1"
    requirement_text: "Cryptographic keys used to protect stored account data are secured"
    properties:
      - FG_AES_FUNC_001
      - FG_AES_FUNC_002
      - FG_AES_TIME_001
      - FG_AES_TIME_002
      - FG_HSM_KEY_002
    verification_status: null  # populated by compliance_report.py
    
  - requirement_id: "3.6.1"
    requirement_text: "Strong cryptography key management processes and procedures are defined"
    properties:
      - FG_AES_FUNC_004
      - FG_RSA_FUNC_002
      - FG_HSM_KEY_001
    verification_status: null
```

### 4.2 Report Generation

```bash
# Generate a PCI-DSS compliance report
python tools/compliance_report.py \
  --properties crypto/aes256 hsm/key_lifecycle \
  --standard pci-dss \
  --results results/aes256_run.json \
  --output reports/pci_dss_coverage.html
```

Output is an HTML report showing:
- Which PCI-DSS requirements have formal verification coverage
- Which properties passed/failed/were not run
- Coverage gaps (requirements with no mapped properties)
- Evidence trail for auditors

---

## 5. Reference Designs

FormalGuard includes minimal reference RTL implementations for testing and demonstration purposes only. These are not production-quality implementations.

| Design | Description | Purpose |
|--------|-------------|---------|
| `aes256_core` | Textbook AES-256 in SystemVerilog | Test crypto properties, demonstrate binding |
| `simple_hsm` | FSM-based HSM with key storage, auth, and tamper input | Test HSM properties |
| `tx_pipeline` | 4-stage transaction pipeline with checksum | Test transaction properties |
| `vuln_aes` | Intentionally vulnerable AES with timing leak | Demonstrate that FG_AES_TIME_001 catches the bug |
| `vuln_hsm` | HSM that fails to zeroize completely | Demonstrate that FG_HSM_KEY_005 catches the bug |

Vulnerable reference designs are critical for demonstrating value — they show that the properties actually catch real bugs.

---

## 6. Tool Compatibility

FormalGuard targets IEEE 1800-2017 SystemVerilog. Properties should work with:

| Tool | Vendor | Status |
|------|--------|--------|
| VC Formal | Synopsys | Primary development target |
| JasperGold | Cadence | Supported |
| OneSpin 360 | Siemens | Supported |
| SymbiYosys | Open-source (YosysHQ) | Best-effort (subset of SVA) |
| EBMC | Open-source | Best-effort (bounded model checking) |

For open-source tool users, FormalGuard provides a compatibility layer that translates full SVA into the subset supported by SymbiYosys where possible, with clear documentation of which properties require commercial tools.

---

## 7. Naming Conventions

### 7.1 Property IDs

Format: `FG_{DOMAIN}_{CATEGORY}_{NNN}`

- `FG` — FormalGuard prefix
- `DOMAIN` — `AES`, `RSA`, `SHA`, `ECDSA`, `HSM`, `TX`, `SC`
- `CATEGORY` — `FUNC` (functional), `TIME` (timing), `FAULT` (fault), `KEY` (key management), `AUTH` (authentication), `TAMP` (tamper), `ATOM` (atomicity), `ISOL` (isolation), `INTEG` (integrity), `ORDER` (ordering), `CT` (constant-time), `PWR` (power), `DIF` (data-independent flow), `NONCE` (nonce management)
- `NNN` — three-digit sequential number

### 7.2 File Naming

- Properties: `{domain}_{category}.sv` (e.g., `aes_functional.sv`)
- Compliance mappings: `mapping.yaml` within standard directory
- Reference designs: Descriptive directory names matching the domain

---

## 8. Quality Criteria

Every property in the core library must satisfy:

1. **Traceable** — maps to at least one compliance requirement
2. **Testable** — passes on at least one known-good reference design
3. **Falsifiable** — fails on at least one known-bad (vulnerable) reference design
4. **Documented** — has a README explaining intent, assumptions, and limitations
5. **Portable** — uses only IEEE 1800-2017 standard SVA (no vendor extensions in core)
6. **Reviewed** — approved by at least one domain expert (verification or security)

---

## 9. Security Considerations

FormalGuard properties describe security requirements — they do not implement security mechanisms. Users must understand:

- **Formal verification proves properties about a model, not about silicon.** Manufacturing defects, analog effects, and environmental attacks are outside the scope of RTL formal verification.
- **Properties are necessary but not sufficient.** Passing all FormalGuard properties does not guarantee a secure system. It guarantees that the verified properties hold on the verified model.
- **Reference designs are for testing only.** Never use FormalGuard reference RTL in production.
- **Compliance mappings are informational.** FormalGuard does not replace qualified security assessors (QSAs) or formal compliance audits. It provides evidence that supports those audits.
