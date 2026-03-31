"""
FormalGuard — HSM Property Tests
==================================
Tests for HSM property file structure and formal verification
integration (SymbiYosys-dependent tests are skipped without it).

Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
SPDX-License-Identifier: Apache-2.0
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SBY = shutil.which("sby")
PROPERTY_ID_PATTERN = re.compile(r"FG_HSM_[A-Z]+_\d{3}")

requires_sby = pytest.mark.skipif(
    SBY is None,
    reason="SymbiYosys (sby) not installed — skipping formal verification tests"
)


class TestHSMPropertyFiles:
    """Verify HSM property files exist and contain expected properties."""

    KEY_LIFECYCLE_DIR = REPO_ROOT / "properties" / "hsm" / "key_lifecycle"
    ACCESS_CTRL_DIR = REPO_ROOT / "properties" / "hsm" / "access_control"
    TAMPER_DIR = REPO_ROOT / "properties" / "hsm" / "tamper_response"

    def test_key_generation_exists(self):
        assert (self.KEY_LIFECYCLE_DIR / "key_generation.sv").exists()

    def test_key_storage_exists(self):
        assert (self.KEY_LIFECYCLE_DIR / "key_storage.sv").exists()

    def test_key_rotation_exists(self):
        assert (self.KEY_LIFECYCLE_DIR / "key_rotation.sv").exists()

    def test_key_destruction_exists(self):
        assert (self.KEY_LIFECYCLE_DIR / "key_destruction.sv").exists()

    def test_auth_enforcement_exists(self):
        assert (self.ACCESS_CTRL_DIR / "auth_enforcement.sv").exists()

    def test_tamper_detect_exists(self):
        assert (self.TAMPER_DIR / "tamper_detect.sv").exists()

    def test_tamper_zeroize_exists(self):
        assert (self.TAMPER_DIR / "tamper_zeroize.sv").exists()

    def test_key_lifecycle_properties_contain_asserts(self):
        for sv_file in self.KEY_LIFECYCLE_DIR.glob("*.sv"):
            content = sv_file.read_text()
            assert "assert property" in content, f"{sv_file.name} has no assertions"

    def test_access_control_properties_contain_asserts(self):
        for sv_file in self.ACCESS_CTRL_DIR.glob("*.sv"):
            content = sv_file.read_text()
            assert "assert property" in content, f"{sv_file.name} has no assertions"

    def test_tamper_properties_contain_asserts(self):
        for sv_file in self.TAMPER_DIR.glob("*.sv"):
            content = sv_file.read_text()
            assert "assert property" in content, f"{sv_file.name} has no assertions"

    def test_all_expected_property_ids_present(self):
        """Check that all 11 HSM property IDs exist somewhere in the files."""
        expected_ids = {
            "FG_HSM_KEY_001", "FG_HSM_KEY_002", "FG_HSM_KEY_003",
            "FG_HSM_KEY_004", "FG_HSM_KEY_005",
            "FG_HSM_AUTH_001", "FG_HSM_AUTH_002", "FG_HSM_AUTH_003",
            "FG_HSM_TAMP_001", "FG_HSM_TAMP_002", "FG_HSM_TAMP_003",
        }
        found_ids = set()
        for sv_dir in [self.KEY_LIFECYCLE_DIR, self.ACCESS_CTRL_DIR, self.TAMPER_DIR]:
            for sv_file in sv_dir.glob("*.sv"):
                content = sv_file.read_text()
                found_ids.update(PROPERTY_ID_PATTERN.findall(content))

        missing = expected_ids - found_ids
        assert not missing, f"Missing HSM property IDs: {missing}"


class TestHSMReferenceDesigns:
    """Verify HSM reference design files exist."""

    def test_simple_hsm_exists(self):
        assert (REPO_ROOT / "reference_designs" / "simple_hsm" / "simple_hsm.sv").exists()

    def test_vuln_hsm_exists(self):
        assert (REPO_ROOT / "reference_designs" / "vuln_hsm" / "vuln_hsm.sv").exists()

    def test_simple_hsm_binding_exists(self):
        assert (REPO_ROOT / "reference_designs" / "simple_hsm" / "fg_bind_simple_hsm.sv").exists()

    def test_vuln_hsm_binding_exists(self):
        assert (REPO_ROOT / "reference_designs" / "vuln_hsm" / "fg_bind_vuln_hsm.sv").exists()

    def test_simple_hsm_sby_exists(self):
        assert (REPO_ROOT / "reference_designs" / "simple_hsm" / "simple_hsm.sby").exists()

    def test_vuln_hsm_sby_exists(self):
        assert (REPO_ROOT / "reference_designs" / "vuln_hsm" / "vuln_hsm.sby").exists()


@requires_sby
class TestHSMFormalVerification:
    """Integration tests requiring SymbiYosys."""

    def test_simple_hsm_proves(self):
        result = subprocess.run(
            ["sby", "-f", "simple_hsm.sby"],
            cwd=REPO_ROOT / "reference_designs" / "simple_hsm",
            capture_output=True, text=True, timeout=600,
        )
        assert result.returncode == 0, f"simple_hsm failed:\n{result.stdout}\n{result.stderr}"

    def test_vuln_hsm_zeroization_fails(self):
        result = subprocess.run(
            ["sby", "-f", "vuln_hsm.sby"],
            cwd=REPO_ROOT / "reference_designs" / "vuln_hsm",
            capture_output=True, text=True, timeout=600,
        )
        assert result.returncode != 0, "Expected zeroization failures on vuln_hsm"
