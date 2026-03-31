#!/usr/bin/env python3
"""
FormalGuard — Coverage Dashboard
==================================
Generates an HTML dashboard showing property coverage across all
compliance standards, property domains, and verification status.

Usage:
    python tools/coverage_dashboard.py --output reports/dashboard.html
    python tools/coverage_dashboard.py --results results/ --output reports/dashboard.html

Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
SPDX-License-Identifier: Apache-2.0
"""

import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
import yaml

REPO_ROOT = Path(__file__).parent.parent
COMPLIANCE_DIR = REPO_ROOT / "compliance"
PROPERTIES_DIR = REPO_ROOT / "properties"

PROPERTY_ID_PATTERN = re.compile(r"(FG_[A-Z]+_[A-Z]+_\d{3})")

DOMAIN_NAMES = {
    "AES": "AES-256",
    "RSA": "RSA",
    "SHA": "SHA-256",
    "ECDSA": "ECDSA",
    "HSM": "HSM",
    "TX": "Transaction",
    "SC": "Side-Channel",
}


def discover_properties() -> dict[str, list[str]]:
    """Scan property files and return {domain: [property_ids]}."""
    domains: dict[str, list[str]] = defaultdict(list)
    for sv_file in PROPERTIES_DIR.rglob("*.sv"):
        content = sv_file.read_text()
        for match in PROPERTY_ID_PATTERN.finditer(content):
            prop_id = match.group(1)
            parts = prop_id.split("_")
            if len(parts) >= 3:
                domain = parts[1]
                if prop_id not in domains[domain]:
                    domains[domain].append(prop_id)
    # Sort each domain's properties
    for domain in domains:
        domains[domain].sort()
    return dict(domains)


def load_all_standards() -> dict[str, dict]:
    """Load all compliance mapping YAML files."""
    standards = {}
    for mapping_file in COMPLIANCE_DIR.rglob("mapping.yaml"):
        with open(mapping_file) as f:
            data = yaml.safe_load(f)
        if data and data.get("mappings"):
            key = data["standard"]
            standards[key] = data
    return standards


def compute_standard_coverage(standard_data: dict, all_props: set[str]) -> dict:
    """Compute coverage metrics for a single standard."""
    total_reqs = len(standard_data.get("mappings", []))
    mapped_props = set()
    for mapping in standard_data.get("mappings", []):
        mapped_props.update(mapping.get("properties", []))

    return {
        "name": standard_data["standard"],
        "version": standard_data.get("version", ""),
        "total_requirements": total_reqs,
        "mapped_properties": len(mapped_props),
        "total_properties": len(all_props),
        "coverage_pct": (len(mapped_props) / len(all_props) * 100) if all_props else 0,
    }


def generate_dashboard_html(
    domains: dict[str, list[str]],
    standards: dict[str, dict],
    output_path: Path,
) -> None:
    """Generate the coverage dashboard HTML."""
    all_props = set()
    for props in domains.values():
        all_props.update(props)

    total_props = len(all_props)
    total_standards = len(standards)

    # Standard coverage
    std_metrics = []
    for key, data in sorted(standards.items()):
        std_metrics.append(compute_standard_coverage(data, all_props))

    # Build cross-reference: property → standards
    prop_to_standards: dict[str, list[str]] = defaultdict(list)
    for std_name, std_data in standards.items():
        for mapping in std_data.get("mappings", []):
            for prop_id in mapping.get("properties", []):
                if std_name not in prop_to_standards[prop_id]:
                    prop_to_standards[prop_id].append(std_name)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>FormalGuard Coverage Dashboard</title>
  <style>
    :root {{ --pass: #22c55e; --warn: #f59e0b; --gray: #9ca3af; --bg: #f8fafc; }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, sans-serif; background: var(--bg); padding: 2rem; color: #1e293b; }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    h1 {{ font-size: 1.5rem; margin-bottom: 0.5rem; }}
    .subtitle {{ color: #64748b; margin-bottom: 2rem; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
    .card {{ background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1.5rem; text-align: center; }}
    .card-value {{ font-size: 2rem; font-weight: 700; }}
    .card-label {{ font-size: 0.8rem; color: #64748b; text-transform: uppercase; }}
    h2 {{ font-size: 1.2rem; margin: 1.5rem 0 1rem; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; margin-bottom: 2rem; }}
    th {{ background: #f1f5f9; padding: 0.6rem 1rem; text-align: left; font-size: 0.8rem; text-transform: uppercase; color: #64748b; }}
    td {{ padding: 0.6rem 1rem; border-top: 1px solid #e2e8f0; font-size: 0.9rem; }}
    .mono {{ font-family: monospace; font-size: 0.85rem; }}
    .bar {{ height: 8px; background: #e2e8f0; border-radius: 4px; overflow: hidden; }}
    .bar-fill {{ height: 100%; background: var(--pass); border-radius: 4px; }}
    footer {{ text-align: center; color: #94a3b8; font-size: 0.8rem; margin-top: 2rem; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>FormalGuard Coverage Dashboard</h1>
    <div class="subtitle">Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} | All phases</div>

    <div class="grid">
      <div class="card">
        <div class="card-value">{total_props}</div>
        <div class="card-label">Total Properties</div>
      </div>
      <div class="card">
        <div class="card-value">{len(domains)}</div>
        <div class="card-label">Domains</div>
      </div>
      <div class="card">
        <div class="card-value">{total_standards}</div>
        <div class="card-label">Standards</div>
      </div>
      <div class="card">
        <div class="card-value">{sum(m['total_requirements'] for m in std_metrics)}</div>
        <div class="card-label">Requirements Mapped</div>
      </div>
    </div>

    <h2>Properties by Domain</h2>
    <table>
      <thead><tr><th>Domain</th><th>Properties</th><th>Count</th><th>Standards Coverage</th></tr></thead>
      <tbody>"""

    for domain in sorted(domains.keys()):
        props = domains[domain]
        name = DOMAIN_NAMES.get(domain, domain)
        # Count how many standards reference this domain's properties
        stds = set()
        for p in props:
            stds.update(prop_to_standards.get(p, []))
        html += f"""
        <tr>
          <td><strong>{name}</strong></td>
          <td class="mono">{', '.join(props)}</td>
          <td>{len(props)}</td>
          <td>{len(stds)} standard(s)</td>
        </tr>"""

    html += """
      </tbody>
    </table>

    <h2>Compliance Standards Coverage</h2>
    <table>
      <thead><tr><th>Standard</th><th>Version</th><th>Requirements</th><th>Properties Referenced</th><th>Coverage</th></tr></thead>
      <tbody>"""

    for m in std_metrics:
        pct = m["coverage_pct"]
        html += f"""
        <tr>
          <td><strong>{m['name']}</strong></td>
          <td>{m['version']}</td>
          <td>{m['total_requirements']}</td>
          <td>{m['mapped_properties']}</td>
          <td>
            <div class="bar"><div class="bar-fill" style="width:{pct:.0f}%"></div></div>
            {pct:.1f}%
          </td>
        </tr>"""

    html += f"""
      </tbody>
    </table>

    <footer>Generated by FormalGuard Coverage Dashboard</footer>
  </div>
</body>
</html>"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(html)


@click.command()
@click.option("--output", "-o", type=click.Path(path_type=Path),
              default=REPO_ROOT / "reports" / "dashboard.html",
              help="Output HTML dashboard path")
def cli(output: Path):
    """Generate the FormalGuard coverage dashboard."""
    domains = discover_properties()
    standards = load_all_standards()

    total = sum(len(v) for v in domains.values())
    click.echo(f"Discovered {total} properties across {len(domains)} domains")
    click.echo(f"Loaded {len(standards)} compliance standards")

    generate_dashboard_html(domains, standards, output)
    click.echo(f"Dashboard generated: {output}")


if __name__ == "__main__":
    cli()
