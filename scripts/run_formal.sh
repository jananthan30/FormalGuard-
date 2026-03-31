#!/usr/bin/env bash
# FormalGuard — Formal Verification Tool Abstraction Layer
# =========================================================
# Auto-detects available formal verification tools and runs
# the appropriate one. Prefers open-source (SymbiYosys) for
# CI compatibility; falls back to commercial tools if available.
#
# Usage: ./scripts/run_formal.sh <sby_config_or_directory>

set -euo pipefail

SBY_FILE="${1:?Usage: run_formal.sh <path-to-.sby-file>}"

if [[ ! -f "$SBY_FILE" ]]; then
    echo "ERROR: SymbiYosys config not found: $SBY_FILE"
    exit 1
fi

# --- Tool Detection ---

detect_tool() {
    if command -v sby &>/dev/null; then
        echo "symbiyosys"
    elif command -v vcf &>/dev/null; then
        echo "vc_formal"
    elif command -v jg &>/dev/null; then
        echo "jaspergold"
    elif command -v onespin &>/dev/null; then
        echo "onespin"
    else
        echo "none"
    fi
}

TOOL=$(detect_tool)
echo "FormalGuard: Detected tool — $TOOL"

case "$TOOL" in
    symbiyosys)
        echo "Running SymbiYosys..."
        sby -f "$SBY_FILE"
        ;;
    vc_formal)
        echo "VC Formal detected. Please run manually with your project TCL script."
        echo "SymbiYosys (.sby) configs are not directly compatible with VC Formal."
        echo "See docs/getting-started.md for VC Formal integration guidance."
        exit 1
        ;;
    jaspergold)
        echo "JasperGold detected. Please run manually with your project TCL script."
        echo "See docs/getting-started.md for JasperGold integration guidance."
        exit 1
        ;;
    onespin)
        echo "OneSpin detected. Please run manually with your project setup."
        echo "See docs/getting-started.md for OneSpin integration guidance."
        exit 1
        ;;
    none)
        echo "ERROR: No supported formal verification tool found."
        echo ""
        echo "Supported tools:"
        echo "  - SymbiYosys (open-source): https://github.com/YosysHQ/sby"
        echo "  - Synopsys VC Formal"
        echo "  - Cadence JasperGold"
        echo "  - Siemens OneSpin 360"
        echo ""
        echo "Install SymbiYosys for open-source formal verification:"
        echo "  https://symbiyosys.readthedocs.io/en/latest/install.html"
        exit 1
        ;;
esac
