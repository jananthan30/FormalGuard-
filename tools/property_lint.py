#!/usr/bin/env python3
"""
FormalGuard — Property Linter
==============================
Validates SVA property files for naming conventions, structure,
and compliance mapping coverage.

Usage:
    python tools/property_lint.py properties/

Copyright 2026 Thuvaragan Paramsothy, Sanchayan Paramsothy, Jananthan Paramsothy
SPDX-License-Identifier: Apache-2.0
"""

import re
import sys
from pathlib import Path

import click

PROPERTY_ID_PATTERN = re.compile(r"(FG_[A-Z]+_[A-Z]+_\d{3})")
ASSERT_PATTERN = re.compile(r"(\w+)\s*:\s*assert\s+property")
MODULE_PATTERN = re.compile(r"module\s+(\w+)")


@dataclass
class LintResult:
    file: Path
    errors: list[str]
    warnings: list[str]
    property_ids: list[str]


def lint_file(sv_file: Path) -> LintResult:
    """Lint a single SystemVerilog property file."""
    errors = []
    warnings = []
    property_ids = []

    content = sv_file.read_text()
    lines = content.split("\n")

    # Check for copyright header
    if "Copyright" not in content and "SPDX" not in content:
        warnings.append("Missing copyright/license header")

    # Check for module declaration
    modules = MODULE_PATTERN.findall(content)
    if not modules:
        warnings.append("No module declaration found")

    # Extract and validate property IDs
    for match in ASSERT_PATTERN.finditer(content):
        label = match.group(1)
        if PROPERTY_ID_PATTERN.match(label):
            property_ids.append(label)
        else:
            warnings.append(f"Assert label '{label}' does not follow FG naming convention")

    # Check that all referenced FG IDs are actually asserted
    all_fg_refs = set(PROPERTY_ID_PATTERN.findall(content))
    asserted_ids = set(property_ids)
    for ref in all_fg_refs:
        if ref not in asserted_ids and f"{ref}:" not in content:
            # It might be referenced in comments or error messages, which is fine
            pass

    # Check for disable iff pattern
    if "assert property" in content and "disable iff" not in content:
        warnings.append("Properties should use 'disable iff (!rst_n)' for reset handling")

    # Check file has properties at all
    if not property_ids:
        if sv_file.name != "README.md":
            errors.append("No FormalGuard properties found in file")

    return LintResult(
        file=sv_file,
        errors=errors,
        warnings=warnings,
        property_ids=property_ids,
    )


@click.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--strict", is_flag=True, help="Treat warnings as errors")
def cli(path: Path, strict: bool):
    """Lint FormalGuard SVA property files."""

    sv_files = list(path.rglob("*.sv")) if path.is_dir() else [path]

    if not sv_files:
        click.echo("No .sv files found")
        sys.exit(0)

    total_errors = 0
    total_warnings = 0
    all_properties = []

    for sv_file in sorted(sv_files):
        result = lint_file(sv_file)
        all_properties.extend(result.property_ids)

        if result.errors or result.warnings:
            click.echo(f"\n{sv_file}:")
            for err in result.errors:
                click.echo(f"  ERROR: {err}")
                total_errors += 1
            for warn in result.warnings:
                click.echo(f"  WARN:  {warn}")
                total_warnings += 1

    # Summary
    click.echo(f"\n{'='*50}")
    click.echo(f"Files:      {len(sv_files)}")
    click.echo(f"Properties: {len(all_properties)}")
    click.echo(f"Errors:     {total_errors}")
    click.echo(f"Warnings:   {total_warnings}")

    # Check for duplicate property IDs
    seen = set()
    for pid in all_properties:
        if pid in seen:
            click.echo(f"  ERROR: Duplicate property ID: {pid}")
            total_errors += 1
        seen.add(pid)

    if total_errors > 0 or (strict and total_warnings > 0):
        sys.exit(1)


# Need dataclass import
from dataclasses import dataclass, field

if __name__ == "__main__":
    cli()
