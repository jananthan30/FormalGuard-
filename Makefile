# FormalGuard — Top-Level Makefile
# ================================

PYTHON ?= python3
PYTEST ?= pytest
SBY    ?= sby

# Property directories
PROP_DIR     = properties
REF_DIR      = reference_designs
COMP_DIR     = compliance
TOOLS_DIR    = tools
TESTS_DIR    = tests
REPORTS_DIR  = reports

.PHONY: all lint verify-aes verify-hsm verify-tx verify-all \
        compliance-report test clean help

all: verify-all test compliance-report

help:
	@echo "FormalGuard Makefile Targets:"
	@echo "  verify-aes        — Run formal verification on AES-256 reference designs"
	@echo "  verify-hsm        — Run formal verification on HSM reference designs"
	@echo "  verify-tx         — Run formal verification on transaction pipeline"
	@echo "  verify-all        — Run all formal verification targets"
	@echo "  compliance-report — Generate PCI-DSS compliance coverage report"
	@echo "  lint              — Lint SVA properties and Python code"
	@echo "  test              — Run Python test suite"
	@echo "  clean             — Remove generated outputs"

# ---------- Formal Verification ----------

verify-aes:
	@echo "=== Verifying AES-256 (known-good) ==="
	$(MAKE) -C $(REF_DIR)/aes256_core verify
	@echo "=== Verifying AES-256 (vulnerable — expect timing failures) ==="
	-$(MAKE) -C $(REF_DIR)/vuln_aes verify

verify-hsm:
	@echo "=== Verifying HSM (known-good) ==="
	$(MAKE) -C $(REF_DIR)/simple_hsm verify
	@echo "=== Verifying HSM (vulnerable — expect zeroization failures) ==="
	-$(MAKE) -C $(REF_DIR)/vuln_hsm verify

verify-tx:
	@echo "=== Verifying Transaction Pipeline ==="
	$(MAKE) -C $(REF_DIR)/tx_pipeline verify

verify-all: verify-aes verify-hsm verify-tx

# ---------- Compliance Reporting ----------

compliance-report:
	@mkdir -p $(REPORTS_DIR)
	$(PYTHON) $(TOOLS_DIR)/compliance_report.py \
		--standard pci-dss \
		--output $(REPORTS_DIR)/pci_dss_coverage.html

# ---------- Linting ----------

lint:
	@echo "=== Linting Python ==="
	$(PYTHON) -m ruff check $(TOOLS_DIR)/ $(TESTS_DIR)/
	@echo "=== Linting SVA properties ==="
	$(PYTHON) $(TOOLS_DIR)/property_lint.py $(PROP_DIR)/

# ---------- Testing ----------

test:
	$(PYTEST) $(TESTS_DIR)/ -v

# ---------- Cleanup ----------

clean:
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	find . -name "*_prove" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name "*_bmc" -type d -exec rm -rf {} + 2>/dev/null || true
	rm -rf $(REPORTS_DIR)/*.html $(REPORTS_DIR)/*.json
	rm -rf build/ work/ .pytest_cache/
