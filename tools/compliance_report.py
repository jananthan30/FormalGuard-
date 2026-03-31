#!/usr/bin/env python3
"""
FormalGuard — Compliance Report Generator
==========================================
Generates HTML compliance coverage reports by cross-referencing formal
verification results with compliance standard mappings.

Usage:
    python tools/compliance_report.py --standard pci-dss --output reports/pci_dss.html
    python tools/compliance_report.py --standard pci-dss --results results/run.json
    python tools/compliance_report.py --standard pci-dss --dry-run

Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
SPDX-License-Identifier: Apache-2.0
"""

import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
import yaml
from jinja2 import Environment, FileSystemLoader

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

PROPERTY_ID_PATTERN = re.compile(r"^FG_[A-Z]+_[A-Z]+_\d{3}$")

STANDARD_DIR_MAP = {
    "pci-dss": "pci_dss",
    "swift-csp": "swift_csp",
    "sox": "sox",
    "iso27001": "iso27001",
    "fips-140-3": "fips_140_3",
}


@dataclass
class PropertyResult:
    """Result of formal verification for a single property."""
    property_id: str
    status: str  # "proven", "failed", "error", "not_run"
    tool: str = "unknown"
    timestamp: str = ""
    details: str = ""


@dataclass
class RequirementMapping:
    """A single compliance requirement and its mapped properties."""
    requirement_id: str
    requirement_text: str
    properties: list[str] = field(default_factory=list)
    verification_status: Optional[str] = None
    notes: str = ""


@dataclass
class CoverageMetrics:
    """Aggregate coverage statistics for a compliance standard."""
    total_requirements: int = 0
    covered_requirements: int = 0  # At least one property mapped
    proven_requirements: int = 0   # All mapped properties proven
    failed_requirements: int = 0   # At least one property failed
    not_run_requirements: int = 0  # Properties mapped but not verified
    total_properties: int = 0
    proven_properties: int = 0
    failed_properties: int = 0

    @property
    def coverage_percent(self) -> float:
        if self.total_requirements == 0:
            return 0.0
        return (self.covered_requirements / self.total_requirements) * 100

    @property
    def proven_percent(self) -> float:
        if self.total_properties == 0:
            return 0.0
        return (self.proven_properties / self.total_properties) * 100


# ---------------------------------------------------------------------------
# Compliance Mapper
# ---------------------------------------------------------------------------

class ComplianceMapper:
    """Loads and queries compliance mapping YAML files."""

    def __init__(self, compliance_dir: Path):
        self.compliance_dir = compliance_dir
        self.mappings: list[RequirementMapping] = []
        self.standard_name = ""
        self.standard_version = ""

    def load(self, standard_key: str) -> None:
        dir_name = STANDARD_DIR_MAP.get(standard_key)
        if not dir_name:
            raise ValueError(
                f"Unknown standard: {standard_key}. "
                f"Available: {', '.join(STANDARD_DIR_MAP.keys())}"
            )

        mapping_file = self.compliance_dir / dir_name / "mapping.yaml"
        if not mapping_file.exists():
            raise FileNotFoundError(f"Mapping file not found: {mapping_file}")

        with open(mapping_file) as f:
            data = yaml.safe_load(f)

        self.standard_name = data.get("standard", standard_key)
        self.standard_version = data.get("version", "unknown")

        self.mappings = []
        for entry in data.get("mappings", []):
            self.mappings.append(RequirementMapping(
                requirement_id=entry["requirement_id"],
                requirement_text=entry["requirement_text"],
                properties=entry.get("properties", []),
                verification_status=entry.get("verification_status"),
                notes=entry.get("notes", ""),
            ))

    def get_all_property_ids(self) -> set[str]:
        ids = set()
        for m in self.mappings:
            ids.update(m.properties)
        return ids

    def requirements_for_property(self, prop_id: str) -> list[RequirementMapping]:
        return [m for m in self.mappings if prop_id in m.properties]

    def properties_for_requirement(self, req_id: str) -> list[str]:
        for m in self.mappings:
            if m.requirement_id == req_id:
                return m.properties
        return []


# ---------------------------------------------------------------------------
# Results Parser
# ---------------------------------------------------------------------------

class ResultsParser:
    """Parses formal verification results from various tool formats."""

    @staticmethod
    def parse_json(results_file: Path) -> dict[str, PropertyResult]:
        """Parse FormalGuard standardized JSON results format."""
        results = {}
        with open(results_file) as f:
            data = json.load(f)

        for entry in data.get("results", []):
            prop_id = entry["property_id"]
            results[prop_id] = PropertyResult(
                property_id=prop_id,
                status=entry.get("status", "not_run"),
                tool=entry.get("tool", "unknown"),
                timestamp=entry.get("timestamp", ""),
                details=entry.get("details", ""),
            )
        return results

    @staticmethod
    def parse_sby_log(log_file: Path) -> dict[str, PropertyResult]:
        """Parse SymbiYosys log output for property results."""
        results = {}
        if not log_file.exists():
            return results

        with open(log_file) as f:
            for line in f:
                # SymbiYosys reports: "Assert failed: FG_AES_TIME_001"
                # or "Proved assertion: FG_AES_FUNC_001"
                if "Assert failed" in line or "failed" in line.lower():
                    match = re.search(r"(FG_[A-Z]+_[A-Z]+_\d{3})", line)
                    if match:
                        prop_id = match.group(1)
                        results[prop_id] = PropertyResult(
                            property_id=prop_id,
                            status="failed",
                            tool="SymbiYosys",
                        )
                elif "Proved" in line or "proven" in line.lower():
                    match = re.search(r"(FG_[A-Z]+_[A-Z]+_\d{3})", line)
                    if match:
                        prop_id = match.group(1)
                        results[prop_id] = PropertyResult(
                            property_id=prop_id,
                            status="proven",
                            tool="SymbiYosys",
                        )
        return results


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Generates compliance coverage reports."""

    def __init__(
        self,
        mapper: ComplianceMapper,
        results: dict[str, PropertyResult],
    ):
        self.mapper = mapper
        self.results = results

    def compute_metrics(self) -> CoverageMetrics:
        metrics = CoverageMetrics()
        metrics.total_requirements = len(self.mapper.mappings)

        all_props = set()
        for mapping in self.mapper.mappings:
            if mapping.properties:
                metrics.covered_requirements += 1

            all_proven = True
            any_failed = False
            any_run = False

            for prop_id in mapping.properties:
                all_props.add(prop_id)
                result = self.results.get(prop_id)
                if result:
                    any_run = True
                    if result.status == "proven":
                        metrics.proven_properties += 1
                    elif result.status == "failed":
                        metrics.failed_properties += 1
                        any_failed = True
                        all_proven = False
                    else:
                        all_proven = False
                else:
                    all_proven = False

            if any_failed:
                metrics.failed_requirements += 1
                mapping.verification_status = "failed"
            elif all_proven and mapping.properties and any_run:
                metrics.proven_requirements += 1
                mapping.verification_status = "proven"
            elif mapping.properties and not any_run:
                metrics.not_run_requirements += 1
                mapping.verification_status = "not_run"
            elif mapping.properties:
                mapping.verification_status = "partial"

        metrics.total_properties = len(all_props)
        return metrics

    def generate_html(self, output_path: Path, template_dir: Optional[Path] = None) -> None:
        if template_dir is None:
            template_dir = Path(__file__).parent / "templates"

        metrics = self.compute_metrics()

        env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=True,
        )
        template = env.get_template("compliance_report.html.j2")

        html = template.render(
            standard_name=self.mapper.standard_name,
            standard_version=self.mapper.standard_version,
            generated_at=datetime.now().isoformat(),
            metrics=metrics,
            mappings=self.mapper.mappings,
            results=self.results,
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(html)

    def generate_summary(self) -> str:
        metrics = self.compute_metrics()
        lines = [
            f"=== FormalGuard Compliance Report: {self.mapper.standard_name} v{self.mapper.standard_version} ===",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "",
            f"Requirements: {metrics.total_requirements} total, "
            f"{metrics.covered_requirements} with properties mapped",
            f"  Proven:  {metrics.proven_requirements}",
            f"  Failed:  {metrics.failed_requirements}",
            f"  Not run: {metrics.not_run_requirements}",
            "",
            f"Properties: {metrics.total_properties} total",
            f"  Proven: {metrics.proven_properties} ({metrics.proven_percent:.1f}%)",
            f"  Failed: {metrics.failed_properties}",
            "",
        ]

        # Per-requirement breakdown
        for mapping in self.mapper.mappings:
            status_icon = {
                "proven": "[PASS]",
                "failed": "[FAIL]",
                "partial": "[PART]",
                "not_run": "[----]",
            }.get(mapping.verification_status, "[    ]")

            lines.append(
                f"  {status_icon} {mapping.requirement_id}: "
                f"{mapping.requirement_text[:60]}..."
            )
            for prop_id in mapping.properties:
                result = self.results.get(prop_id)
                prop_status = result.status if result else "not_run"
                lines.append(f"         {prop_id}: {prop_status}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.command()
@click.option(
    "--standard", "-s",
    required=True,
    type=click.Choice(list(STANDARD_DIR_MAP.keys())),
    help="Compliance standard to report on",
)
@click.option(
    "--results", "-r",
    type=click.Path(exists=True, path_type=Path),
    help="Path to verification results JSON file",
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    help="Output HTML report path",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Print summary to stdout without generating HTML",
)
def cli(standard: str, results: Optional[Path], output: Optional[Path], dry_run: bool):
    """Generate a compliance coverage report for FormalGuard verification results."""

    # Find compliance directory
    repo_root = Path(__file__).parent.parent
    compliance_dir = repo_root / "compliance"

    # Load mapping
    mapper = ComplianceMapper(compliance_dir)
    try:
        mapper.load(standard)
    except (FileNotFoundError, ValueError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    # Load results (if provided)
    verification_results: dict[str, PropertyResult] = {}
    if results:
        try:
            verification_results = ResultsParser.parse_json(results)
        except (json.JSONDecodeError, KeyError) as e:
            click.echo(f"Error parsing results: {e}", err=True)
            sys.exit(1)

    # Generate report
    generator = ReportGenerator(mapper, verification_results)

    if dry_run:
        click.echo(generator.generate_summary())
        return

    if output is None:
        output = repo_root / "reports" / f"{STANDARD_DIR_MAP[standard]}_coverage.html"

    generator.generate_html(output)
    click.echo(f"Report generated: {output}")


if __name__ == "__main__":
    cli()
