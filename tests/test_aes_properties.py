"""
FormalGuard — AES Property Integration Tests
=============================================
Integration tests that run SymbiYosys on reference designs and verify
that properties produce expected results.

These tests are SKIPPED if SymbiYosys (sby) is not installed.
In CI, SymbiYosys is available via the hdlc/formal Docker image.

Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
SPDX-License-Identifier: Apache-2.0
"""

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SBY = shutil.which("sby")

requires_sby = pytest.mark.skipif(
    SBY is None,
    reason="SymbiYosys (sby) not installed — skipping formal verification tests"
)


@requires_sby
class TestAES256Core:
    """Test FormalGuard properties against the known-good AES-256 core."""

    def test_aes256_core_proves(self):
        """All properties should PROVE on the known-good design."""
        result = subprocess.run(
            ["sby", "-f", "aes256_core.sby"],
            cwd=REPO_ROOT / "reference_designs" / "aes256_core",
            capture_output=True,
            text=True,
            timeout=600,
        )
        assert result.returncode == 0, (
            f"AES-256 core verification failed:\n{result.stdout}\n{result.stderr}"
        )


@requires_sby
class TestVulnAES:
    """Test FormalGuard properties against the vulnerable AES design."""

    def test_vuln_aes_timing_fails(self):
        """Timing properties should FAIL on the vulnerable design."""
        result = subprocess.run(
            ["sby", "-f", "vuln_aes.sby"],
            cwd=REPO_ROOT / "reference_designs" / "vuln_aes",
            capture_output=True,
            text=True,
            timeout=600,
        )
        # SymbiYosys returns non-zero when assertions fail
        assert result.returncode != 0, (
            "Expected timing property failures on vulnerable AES, but all passed"
        )
        # Verify that the failure is from timing properties specifically
        output = result.stdout + result.stderr
        assert "TIME" in output or "failed" in output.lower(), (
            "Expected timing-related failures in output"
        )


class TestPropertyFiles:
    """Non-formal tests: check that property files exist and are well-formed."""

    AES_PROPERTY_DIR = REPO_ROOT / "properties" / "crypto" / "aes256"

    def test_functional_properties_exist(self):
        assert (self.AES_PROPERTY_DIR / "aes_functional.sv").exists()

    def test_timing_properties_exist(self):
        assert (self.AES_PROPERTY_DIR / "aes_timing.sv").exists()

    def test_fault_properties_exist(self):
        assert (self.AES_PROPERTY_DIR / "aes_fault.sv").exists()

    def test_readme_exists(self):
        assert (self.AES_PROPERTY_DIR / "README.md").exists()

    def test_properties_contain_assert(self):
        """Each property file should contain at least one assert statement."""
        for sv_file in self.AES_PROPERTY_DIR.glob("*.sv"):
            content = sv_file.read_text()
            assert "assert property" in content, (
                f"{sv_file.name} contains no assert statements"
            )

    def test_properties_contain_fg_ids(self):
        """Each property file should contain FG_ property IDs."""
        import re
        pattern = re.compile(r"FG_AES_[A-Z]+_\d{3}")
        for sv_file in self.AES_PROPERTY_DIR.glob("*.sv"):
            content = sv_file.read_text()
            matches = pattern.findall(content)
            assert len(matches) > 0, (
                f"{sv_file.name} contains no FG_AES property IDs"
            )
