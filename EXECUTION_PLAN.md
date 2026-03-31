# FormalGuard — 12-Month Execution Plan

**Objective:** Build a credible, high-impact open-source project that demonstrates original contributions of major significance for both contributors, supporting O-1/EB-1A immigration petitions and establishing thought leadership at the intersection of formal verification and financial security.

---

## Contributor Roles

**Thuvaragan (T)** — All formal verification work: SVA property design, reference RTL, tool integration, verification methodology. Estimated commitment: 8–10 hrs/week.

**Sanchayan (S)** — All financial security domain work: threat models, compliance mappings, tooling/scripts, documentation of banking context, community engagement. Estimated commitment: 8–10 hrs/week.

---

## Phase 1: Foundation (Months 1–3)

**Goal:** Ship a minimal but complete vertical slice — AES-256 verification with PCI-DSS mapping. Enough to demonstrate the concept and attract initial attention.

### Month 1: Setup and Core AES Properties

| Week | Task | Owner | Deliverable |
|------|------|-------|-------------|
| 1 | Create GitHub org, repo, README, SPEC.md, LICENSE (Apache 2.0), CI skeleton | T + S | Public repo live |
| 1 | Set up project communication (shared Notion/Obsidian, weekly sync cadence) | S | Process documented |
| 2 | Write AES-256 functional correctness properties (FG_AES_FUNC_001 through 004) | T | `properties/crypto/aes256/aes_functional.sv` |
| 2 | Draft PCI-DSS compliance mapping for AES properties | S | `compliance/pci_dss/mapping.yaml` (partial) |
| 3 | Write AES-256 timing properties (FG_AES_TIME_001 through 003) | T | `properties/crypto/aes256/aes_timing.sv` |
| 3 | Write financial hardware threat model document for cryptographic modules | S | `docs/threat-models.md` (crypto section) |
| 4 | Build minimal AES-256 reference design (known-good) | T | `reference_designs/aes256_core/` |
| 4 | Build intentionally vulnerable AES (timing leak) | T | `reference_designs/vuln_aes/` |

### Month 2: Binding Layer and First Verification Run

| Week | Task | Owner | Deliverable |
|------|------|-------|-------------|
| 1 | Design and implement binding interface (`fg_aes256_if`) | T | Interface spec + SystemVerilog |
| 1 | Write getting-started documentation | S | `docs/getting-started.md` |
| 2 | Run full formal verification of AES properties on reference designs | T | Pass/fail results documented |
| 2 | Build compliance report generator script (Python) | S | `tools/compliance_report.py` |
| 3 | Demonstrate that timing properties catch the vuln_aes bug | T | Worked example in `examples/aes256_basic/` |
| 3 | Generate first PCI-DSS compliance coverage report | S | Sample HTML report |
| 4 | Write AES fault resistance properties (FG_AES_FAULT_001, 002) | T | `properties/crypto/aes256/aes_fault.sv` |
| 4 | Write property catalog documentation | S | `docs/property-catalog.md` (AES section) |

### Month 3: Polish, Launch, First Publication

| Week | Task | Owner | Deliverable |
|------|------|-------|-------------|
| 1 | Code review, cleanup, consistent naming, CI passing | T + S | Clean repo |
| 1 | Write contributing guidelines | S | `docs/contributing.md` |
| 2 | **Write blog post #1:** "Why Financial Hardware Needs Open-Source Formal Verification" | S (lead), T (review) | Published on Medium/dev.to |
| 2 | Post to Hacker News, Reddit r/FPGA, r/netsec, r/chipdesign | T + S | Community awareness |
| 3 | **Write blog post #2:** "Catching Timing Side-Channels in AES with Formal Verification" (technical) | T (lead), S (review) | Published |
| 3 | Post to verification forums (Verification Academy, DVClub) | T | Forum engagement |
| 4 | Retrospective: assess stars, forks, issues, feedback. Adjust Phase 2 plan. | T + S | Phase 2 refinement |

**Phase 1 Exit Criteria:**
- [ ] 10+ SVA properties verified on reference designs
- [ ] 1 working compliance report
- [ ] 2 published blog posts
- [ ] 50+ GitHub stars (stretch: 100+)
- [ ] At least 3 external issues or discussions from community

---

## Phase 2: Expand Domain Coverage (Months 4–6)

**Goal:** Add HSM and RSA/SHA properties, second compliance standard (SWIFT CSP), and submit first conference paper.

### Month 4: HSM Key Lifecycle Properties

| Week | Task | Owner | Deliverable |
|------|------|-------|-------------|
| 1 | Write HSM key generation and storage properties (FG_HSM_KEY_001 through 003) | T | `properties/hsm/key_lifecycle/` |
| 1 | Write threat model for HSM attacks in banking (key extraction, fault injection) | S | `docs/threat-models.md` (HSM section) |
| 2 | Write HSM key rotation and destruction properties (FG_HSM_KEY_004, 005) | T | Complete key lifecycle suite |
| 2 | Map HSM properties to PCI-DSS and begin SWIFT CSP mapping | S | Updated YAML mappings |
| 3 | Build simple_hsm reference design (FSM with key store, auth, tamper input) | T | `reference_designs/simple_hsm/` |
| 3 | Build vulnerable HSM (incomplete zeroization) | T | `reference_designs/vuln_hsm/` |
| 4 | Verify HSM properties, demonstrate vuln detection | T | `examples/hsm_key_lifecycle/` |
| 4 | Generate combined PCI-DSS + SWIFT CSP compliance report | S | Expanded report tooling |

### Month 5: RSA, SHA, Access Control

| Week | Task | Owner | Deliverable |
|------|------|-------|-------------|
| 1 | Write RSA properties (FG_RSA_FUNC_001, 002, FG_RSA_TIME_001) | T | `properties/crypto/rsa/` |
| 1 | Write SHA-256 properties (FG_SHA_FUNC_001 through 003) | T | `properties/crypto/sha256/` |
| 2 | Write HSM access control properties (FG_HSM_AUTH_001 through 003) | T | `properties/hsm/access_control/` |
| 2 | Write HSM tamper response properties (FG_HSM_TAMP_001 through 003) | T | `properties/hsm/tamper_response/` |
| 3 | Complete SWIFT CSP compliance mapping | S | `compliance/swift_csp/mapping.yaml` |
| 3 | Build property linting tool | S | `tools/property_lint.py` |
| 4 | Full regression: verify all properties across all reference designs | T | CI green, results documented |
| 4 | Update property catalog and getting-started docs | S | Docs current |

### Month 6: Conference Paper and Community Growth

| Week | Task | Owner | Deliverable |
|------|------|-------|-------------|
| 1–2 | **Write conference paper:** "FormalGuard: Bridging Formal Verification and Financial Compliance for Security-Critical Hardware" | T (methodology) + S (domain/compliance) | Draft paper |
| 2 | Identify target venues: DVCon, IEEE HOST (Hardware-Oriented Security and Trust), DAC workshop, SNUG | T + S | Submission targets |
| 3 | Submit paper to chosen venue | T + S | Paper submitted |
| 3 | **Write blog post #3:** "How Banks Can Use Formal Verification for PCI-DSS Hardware Compliance" | S (lead) | Published |
| 4 | Engage with any open issues/PRs from community | T + S | Community health |
| 4 | Retrospective: stars, forks, citations, paper status | T + S | Phase 3 planning |

**Phase 2 Exit Criteria:**
- [ ] 30+ SVA properties across 3 domains
- [ ] 2 compliance standards mapped
- [ ] 1 conference paper submitted
- [ ] 3+ published blog posts total
- [ ] 150+ GitHub stars (stretch: 300+)
- [ ] At least 1 external contributor or PR

---

## Phase 3: Depth, Visibility, Immigration Impact (Months 7–12)

**Goal:** Establish FormalGuard as the definitive open-source resource in this space. Build the evidence portfolio for O-1/EB-1A applications.

### Months 7–8: Transaction Pipeline and Side-Channel Properties

| Task | Owner |
|------|-------|
| Write transaction pipeline properties (atomicity, isolation, integrity, ordering) | T |
| Build tx_pipeline reference design | T |
| Write side-channel resistance properties (constant-time, power-balanced) | T |
| Add SOX 404 compliance mapping for transaction properties | S |
| Begin ISO 27001 compliance mapping | S |
| **Write blog post #4:** "Formal Methods for SWIFT CSP Compliance" | S |
| **Write blog post #5:** "Constant-Time Hardware: Why and How to Formally Verify It" | T |
| Build coverage dashboard tool | S |
| Submit to IEEE/ACM workshop or journal if DVCon/HOST paper accepted | T + S |

### Months 9–10: Open-Source Tool Integration and ECDSA

| Task | Owner |
|------|-------|
| Write SymbiYosys compatibility layer for core properties | T |
| Write ECDSA properties (including nonce reuse detection) | T |
| Begin FIPS 140-3 compliance mapping | S |
| **Present at a meetup or conference** (IEEE local chapter, OWASP, DVClub, BSides) | T and/or S |
| Pursue media coverage: pitch to EE Times, Semiconductor Engineering, The Register | S |
| Seek endorsement letters from professors or senior engineers in verification and fintech security | T + S |

### Months 11–12: Post-Quantum Roadmap and Immigration Filing Preparation

| Task | Owner |
|------|-------|
| Publish roadmap for post-quantum cryptography verification (Kyber, Dilithium properties) | T |
| Write comprehensive project report suitable for O-1/EB-1A petition evidence | S |
| Collect and organize all evidence: GitHub metrics, citations, media mentions, letters, conference acceptances | T + S |
| **Write blog post #6:** "The State of Financial Hardware Security — and What Formal Verification Can Do About It" | T + S |
| Ensure all documentation is publication-quality | S |
| Consult immigration attorney with assembled evidence portfolio | T + S |

**Phase 3 Exit Criteria:**
- [ ] 50+ SVA properties across all domains
- [ ] 4+ compliance standards mapped
- [ ] 1+ conference paper accepted or published
- [ ] 6+ published blog posts
- [ ] 300+ GitHub stars (stretch: 500+)
- [ ] 1+ presentation at a recognized conference/meetup
- [ ] Expert recommendation letters obtained
- [ ] Immigration attorney consulted with evidence portfolio

---

## Immigration Evidence Checklist

Both brothers should track progress against O-1A criteria throughout the project:

### For Thuvaragan (O-1A petition)

| O-1A Criterion | Evidence from FormalGuard | Status |
|----------------|--------------------------|--------|
| Original contributions of major significance | Novel formal verification framework bridging EDA and financial security — no prior open-source equivalent exists | Build |
| Authorship of scholarly articles | Conference paper(s), blog posts with technical depth | Build |
| Judging the work of others | Review community PRs, serve on conference program committees | Build |
| Employment in critical/distinguished capacity | Sr Supervisor at Synopsys (already strong) + FormalGuard project lead | Existing + Build |
| High salary | Synopsys compensation (document) | Existing |
| Published material about the person | Media coverage of FormalGuard, conference bios | Build |

### For Sanchayan (O-1A petition — longer-term)

| O-1A Criterion | Evidence from FormalGuard | Status |
|----------------|--------------------------|--------|
| Original contributions of major significance | Novel compliance-to-verification mapping methodology — first of its kind | Build |
| Authorship of scholarly articles | Co-authored conference paper(s), blog posts on financial hardware security | Build |
| Judging the work of others | Review PRs, judge hackathons, review for security conferences | Build |
| Employment in critical/distinguished capacity | UBS backend security (frame as protecting critical financial infrastructure) | Existing (needs framing) |
| High salary | UBS compensation (document) | Existing |
| Published material about the person | Media coverage, conference bios | Build |

---

## Key Milestones Summary

| Month | Milestone |
|-------|-----------|
| 1 | Repo public, first properties committed |
| 3 | Phase 1 complete, 2 blog posts, initial community traction |
| 6 | Conference paper submitted, 30+ properties, 2 compliance standards |
| 9 | Conference presentation, media outreach, SymbiYosys support |
| 12 | Full evidence portfolio assembled, immigration attorney consultation |

---

## Risk Mitigations

| Risk | Mitigation |
|------|------------|
| Low community traction | Focus on quality over quantity. Even 100 stars from the right people (verification engineers, banking security) is more valuable than 1000 random stars. Target niche communities directly. |
| Time commitment unsustainable | Reduce scope, not quality. Ship fewer properties but keep each one fully documented and verified. A smaller excellent project beats a large mediocre one. |
| Conference paper rejected | Submit to multiple venues. Workshop papers at DAC/HOST have higher acceptance rates. Fallback: self-publish as arXiv preprint (still counts as scholarly work for O-1). |
| IP concerns with employers | FormalGuard uses no proprietary IP from Synopsys or UBS. All properties are original work based on public standards (IEEE, NIST, PCI). Review employer IP policies before starting. Important: do not use Synopsys tools to verify FormalGuard properties for public results — use open-source tools or personal licenses. |
| Thuvaragan's time zone (Sri Lanka) vs Sanchayan (Singapore) | Only 2.5 hour difference. Weekly sync calls are feasible. Async workflow via GitHub issues and PRs is primary. |

---

## Week 1 Action Items

1. **Thuvaragan:** Create GitHub organization `formalguard`, initialize repo with README.md, SPEC.md, LICENSE, folder structure. Start writing FG_AES_FUNC_001.
2. **Sanchayan:** Set up project Notion/wiki, draft initial PCI-DSS mapping YAML, outline threat-models.md crypto section.
3. **Both:** Review each other's employer IP/moonlighting policies. Confirm no conflicts.
4. **Both:** Schedule weekly 30-min sync call (suggest Sunday evening SG / Sunday afternoon SL).
