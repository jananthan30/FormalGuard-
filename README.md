# FormalGuard

**Open-Source Formal Verification Framework for Security-Critical Financial Hardware**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

---

## The Problem

Financial institutions increasingly rely on custom hardware for security — Hardware Security Modules (HSMs), FPGA-based transaction accelerators, secure enclaves, and cryptographic co-processors. These components protect trillions of dollars in daily transactions.

Yet there is **no open-source formal verification framework** specifically designed for financial hardware security. Existing tools (Synopsys VC Formal, Cadence JasperGold, Siemens OneSpin) are proprietary, expensive, and lack domain-specific property libraries for financial compliance. Smaller institutions, fintech startups, and academic researchers are locked out.

FormalGuard bridges this gap.

## What FormalGuard Does

FormalGuard provides a **reusable library of SystemVerilog Assertions (SVA)** and formal verification properties purpose-built for verifying security guarantees in financial hardware. It maps verification properties directly to regulatory and industry compliance requirements (PCI-DSS, SOX, SWIFT CSP, ISO 27001).

### Core Components

- **Cryptographic Module Verification** — SVA property suites for AES-256, RSA, SHA-256/SHA-3, and ECDSA implementations. Proves functional correctness, resistance to fault injection, and timing-invariance.
- **HSM State Machine Verification** — Formal properties for verifying key lifecycle management (generation, storage, rotation, destruction), access control enforcement, and tamper response logic.
- **Secure Transaction Pipeline Verification** — Properties ensuring atomicity, isolation, and integrity of hardware-accelerated financial transaction processing.
- **Side-Channel Resistance Properties** — Formal checks for constant-time execution, power-balanced logic, and data-independent control flow in cryptographic operations.
- **Compliance Mapping Engine** — A structured mapping from each formal property to specific regulatory requirements, enabling auditable verification coverage.

### Who This Is For

- **Hardware security engineers** at banks, payment processors, and fintechs building or integrating HSMs and secure hardware
- **FPGA engineers** implementing real-time transaction processing or cryptographic acceleration
- **Compliance and audit teams** seeking formal evidence that hardware meets regulatory requirements
- **Academic researchers** studying hardware security in financial systems
- **Verification engineers** looking for reusable, domain-specific SVA libraries

## Quick Start

```bash
# Clone the repository
git clone https://github.com/jananthan30/FormalGuard.git
cd formalguard

# Run the AES-256 verification example (requires a SystemVerilog simulator)
cd examples/aes256_basic
make verify

# Generate a compliance coverage report
python tools/compliance_report.py --properties crypto/aes256 --standard pci-dss
```

## Documentation

- [SPEC.md](SPEC.md) — Technical specification and architecture
- [docs/getting-started.md](docs/getting-started.md) — Setup and first verification run
- [docs/property-catalog.md](docs/property-catalog.md) — Complete catalog of verification properties
- [docs/compliance-mapping.md](docs/compliance-mapping.md) — Property-to-regulation mapping reference
- [docs/contributing.md](docs/contributing.md) — How to contribute new properties or compliance mappings

## Project Structure

```
formalguard/
├── README.md
├── SPEC.md
├── LICENSE
├── Makefile
│
├── properties/                    # Core SVA property libraries
│   ├── crypto/                    # Cryptographic module verification
│   │   ├── aes256/
│   │   │   ├── aes_functional.sv        # Correctness properties
│   │   │   ├── aes_timing.sv            # Constant-time execution checks
│   │   │   ├── aes_fault.sv             # Fault injection resistance
│   │   │   └── README.md
│   │   ├── rsa/
│   │   │   ├── rsa_functional.sv
│   │   │   ├── rsa_timing.sv
│   │   │   └── README.md
│   │   ├── sha256/
│   │   │   ├── sha_functional.sv
│   │   │   ├── sha_collision.sv
│   │   │   └── README.md
│   │   └── ecdsa/
│   │       ├── ecdsa_functional.sv
│   │       ├── ecdsa_nonce.sv           # Nonce reuse detection
│   │       └── README.md
│   │
│   ├── hsm/                       # Hardware Security Module verification
│   │   ├── key_lifecycle/
│   │   │   ├── key_generation.sv        # RNG quality, key length enforcement
│   │   │   ├── key_storage.sv           # Secure storage invariants
│   │   │   ├── key_rotation.sv          # Rotation policy enforcement
│   │   │   ├── key_destruction.sv       # Zeroization completeness
│   │   │   └── README.md
│   │   ├── access_control/
│   │   │   ├── auth_enforcement.sv      # Multi-factor authentication checks
│   │   │   ├── role_separation.sv       # Dual-control enforcement
│   │   │   └── README.md
│   │   └── tamper_response/
│   │       ├── tamper_detect.sv         # Physical tamper detection logic
│   │       ├── tamper_zeroize.sv        # Emergency key destruction
│   │       └── README.md
│   │
│   ├── transaction/               # Secure transaction pipeline verification
│   │   ├── atomicity.sv                 # Transaction all-or-nothing guarantee
│   │   ├── isolation.sv                 # Cross-transaction data leakage prevention
│   │   ├── integrity.sv                 # End-to-end data integrity checks
│   │   ├── ordering.sv                  # Transaction ordering guarantees
│   │   └── README.md
│   │
│   └── side_channel/              # Side-channel resistance properties
│       ├── constant_time.sv             # Timing-invariant execution
│       ├── power_balanced.sv            # Balanced power consumption
│       ├── data_independent_flow.sv     # No data-dependent branching
│       └── README.md
│
├── compliance/                    # Regulatory compliance mappings
│   ├── pci_dss/
│   │   ├── mapping.yaml                 # Property → PCI-DSS requirement mapping
│   │   └── README.md
│   ├── swift_csp/
│   │   ├── mapping.yaml
│   │   └── README.md
│   ├── sox/
│   │   ├── mapping.yaml
│   │   └── README.md
│   └── iso27001/
│       ├── mapping.yaml
│       └── README.md
│
├── reference_designs/             # Reference RTL for testing properties
│   ├── aes256_core/               # Minimal AES-256 implementation
│   ├── simple_hsm/                # Simplified HSM state machine
│   └── tx_pipeline/               # Basic transaction pipeline
│
├── examples/                      # Worked verification examples
│   ├── aes256_basic/              # Verify an AES core with FormalGuard properties
│   ├── hsm_key_lifecycle/         # Full HSM key management verification
│   ├── transaction_pipeline/      # Transaction integrity verification
│   └── compliance_audit/          # Generate a PCI-DSS compliance report
│
├── tools/                         # Utility scripts
│   ├── compliance_report.py       # Generate compliance coverage reports
│   ├── property_lint.py           # Lint and validate SVA properties
│   └── coverage_dashboard.py      # Verification coverage visualization
│
├── docs/                          # Documentation
│   ├── getting-started.md
│   ├── property-catalog.md
│   ├── compliance-mapping.md
│   ├── threat-models.md           # Financial hardware threat landscape
│   ├── architecture.md
│   └── contributing.md
│
└── tests/                         # CI tests for property correctness
    ├── test_aes_properties.py
    ├── test_hsm_properties.py
    └── test_compliance_mapping.py
```

## Compliance Standards Supported

| Standard | Coverage | Status |
|----------|----------|--------|
| PCI-DSS v4.0 | Cryptographic hardware requirements (Req 3, 4) | Phase 1 |
| SWIFT CSP | HSM and secure messaging requirements | Phase 2 |
| SOX Section 404 | Hardware controls for financial data integrity | Phase 2 |
| ISO 27001 | Annex A cryptographic controls | Phase 3 |
| FIPS 140-3 | Cryptographic module security levels | Phase 3 |

## Why Open Source?

Formal verification of security-critical hardware should not be gatekept behind six-figure EDA licenses. Financial system security is a public good — the integrity of the systems that process your salary, your savings, and your retirement funds depends on hardware that works correctly. FormalGuard makes it possible for any team to formally verify their financial hardware against real compliance requirements.

## Contributing

We welcome contributions from both the hardware verification and financial security communities. See [docs/contributing.md](docs/contributing.md) for guidelines.

Priority areas for contribution:
- New SVA properties for emerging cryptographic standards (post-quantum algorithms)
- Additional compliance standard mappings (FINMA, MAS, FCA)
- Reference designs for common financial hardware architectures
- Integration guides for open-source formal verification tools (SymbiYosys, EBMC)
- Threat model documentation for specific financial hardware attack surfaces

## Authors

- **Thuvaragan Paramsothy** — Formal verification methodology, SVA property design, tool integration. Sr Supervisor Application Engineering at Synopsys. Expert in VC Formal, functional safety verification, and property verification. B.Eng Electronics & Telecommunication, University of Moratuwa.
- **Sanchayan Paramsothy** — Financial security domain modeling, compliance mapping, threat analysis, tooling. Backend security engineer at UBS. Experience across IBM, NCS Group in financial and enterprise security systems. BSc Computer Engineering, University of Peradeniya.
- **Jananthan Paramsothy** — Project architecture, implementation, and technical documentation.

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.

## Citation

If you use FormalGuard in academic work, please cite:

```bibtex
@software{formalguard2026,
  title={FormalGuard: Open-Source Formal Verification for Security-Critical Financial Hardware},
  author={Paramsothy, Thuvaragan and Paramsothy, Sanchayan and Paramsothy, Jananthan},
  year={2026},
  url={https://github.com/jananthan30/FormalGuard}
}
```
