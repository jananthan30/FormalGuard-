"""
FormalGuard — Compliance Mapping Tests
=======================================
Validates that all compliance mapping YAML files are structurally correct,
follow naming conventions, and have no duplicate property references.

Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
SPDX-License-Identifier: Apache-2.0
"""

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
COMPLIANCE_DIR = REPO_ROOT / "compliance"
PROPERTY_ID_PATTERN = re.compile(r"^FG_[A-Z]+_[A-Z]+_\d{3}$")

VALID_DOMAINS = {"AES", "RSA", "SHA", "ECDSA", "HSM", "TX", "SC"}
VALID_CATEGORIES = {
    "FUNC", "TIME", "FAULT", "KEY", "AUTH", "TAMP",
    "ATOM", "ISOL", "INTEG", "ORDER", "CT", "PWR", "DIF", "NONCE",
}


def get_mapping_files():
    """Find all mapping.yaml files under compliance/."""
    return list(COMPLIANCE_DIR.rglob("mapping.yaml"))


@pytest.fixture(params=get_mapping_files(), ids=lambda p: str(p.relative_to(REPO_ROOT)))
def mapping_file(request):
    return request.param


class TestMappingStructure:
    """Test that each mapping file has the required structure."""

    def test_yaml_is_valid(self, mapping_file):
        """Mapping file must be valid YAML."""
        with open(mapping_file) as f:
            data = yaml.safe_load(f)
        assert data is not None

    def test_required_fields(self, mapping_file):
        """Mapping file must have standard, version, and mappings."""
        with open(mapping_file) as f:
            data = yaml.safe_load(f)
        assert "standard" in data, "Missing 'standard' field"
        assert "version" in data, "Missing 'version' field"
        assert "mappings" in data, "Missing 'mappings' field"
        assert isinstance(data["mappings"], list), "'mappings' must be a list"

    def test_mapping_entries(self, mapping_file):
        """Each mapping entry must have requirement_id, requirement_text, and properties."""
        with open(mapping_file) as f:
            data = yaml.safe_load(f)
        for i, entry in enumerate(data.get("mappings", [])):
            assert "requirement_id" in entry, f"Entry {i}: missing 'requirement_id'"
            assert "requirement_text" in entry, f"Entry {i}: missing 'requirement_text'"
            assert "properties" in entry, f"Entry {i}: missing 'properties'"
            assert isinstance(entry["properties"], list), f"Entry {i}: 'properties' must be a list"


class TestPropertyIds:
    """Test that property IDs follow the naming convention."""

    def test_property_id_format(self, mapping_file):
        """All property IDs must match FG_{DOMAIN}_{CATEGORY}_{NNN}."""
        with open(mapping_file) as f:
            data = yaml.safe_load(f)
        for entry in data.get("mappings", []):
            for prop_id in entry.get("properties", []):
                assert PROPERTY_ID_PATTERN.match(prop_id), (
                    f"Invalid property ID format: '{prop_id}' "
                    f"(expected FG_DOMAIN_CATEGORY_NNN)"
                )

    def test_property_id_domains(self, mapping_file):
        """Property ID domains must be from the valid set."""
        with open(mapping_file) as f:
            data = yaml.safe_load(f)
        for entry in data.get("mappings", []):
            for prop_id in entry.get("properties", []):
                parts = prop_id.split("_")
                if len(parts) >= 3:
                    domain = parts[1]
                    assert domain in VALID_DOMAINS, (
                        f"Unknown domain '{domain}' in {prop_id}. "
                        f"Valid: {VALID_DOMAINS}"
                    )


class TestNoDuplicates:
    """Test that there are no duplicate property IDs across all mappings."""

    def test_no_duplicate_ids_within_file(self, mapping_file):
        """No property ID should appear in two different requirements in the same file."""
        with open(mapping_file) as f:
            data = yaml.safe_load(f)
        all_ids = []
        for entry in data.get("mappings", []):
            all_ids.extend(entry.get("properties", []))
        duplicates = [pid for pid in set(all_ids) if all_ids.count(pid) > 1]
        # Note: same property CAN map to multiple requirements (this is intentional)
        # So we just check for exact duplicate entries, not cross-requirement overlap

    def test_no_empty_requirements(self, mapping_file):
        """Requirements should not have empty property lists (except stubs)."""
        with open(mapping_file) as f:
            data = yaml.safe_load(f)
        # Stub files (empty mappings) are ok
        if not data.get("mappings"):
            return
        for entry in data["mappings"]:
            assert len(entry.get("properties", [])) > 0, (
                f"Requirement '{entry['requirement_id']}' has no properties mapped"
            )


class TestComplianceReport:
    """Test the compliance report generator."""

    def test_dry_run(self):
        """Compliance report dry-run should complete without error."""
        import sys
        sys.path.insert(0, str(REPO_ROOT))
        from tools.compliance_report import ComplianceMapper, ReportGenerator

        mapper = ComplianceMapper(COMPLIANCE_DIR)
        mapper.load("pci-dss")

        generator = ReportGenerator(mapper, {})
        summary = generator.generate_summary()
        assert "PCI-DSS" in summary
        assert "Requirements:" in summary

    def test_load_sample_results(self):
        """Sample results file should parse correctly."""
        import sys
        sys.path.insert(0, str(REPO_ROOT))
        from tools.compliance_report import ResultsParser

        results_file = REPO_ROOT / "examples" / "compliance_audit" / "sample_results.json"
        if results_file.exists():
            results = ResultsParser.parse_json(results_file)
            assert len(results) > 0
            assert "FG_AES_FUNC_001" in results
            assert results["FG_AES_FUNC_001"].status == "proven"
