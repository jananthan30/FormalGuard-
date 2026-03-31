#!/usr/bin/env bash
# FormalGuard — AES-256 Basic Verification Example
# Run from the repository root:
#   bash examples/aes256_basic/run.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

echo "=== FormalGuard AES-256 Verification Example ==="
echo ""

# Step 1: Verify the known-good design
echo "--- Verifying known-good AES-256 core ---"
cd "$REPO_ROOT/reference_designs/aes256_core"
sby -f aes256_core.sby
echo ""
echo "Result: All properties should PROVE."
echo ""

# Step 2: Verify the vulnerable design
echo "--- Verifying vulnerable AES-256 (expect timing failures) ---"
cd "$REPO_ROOT/reference_designs/vuln_aes"
sby -f vuln_aes.sby || true
echo ""
echo "Result: Timing properties should FAIL, functional should PASS."
echo ""

echo "=== Verification complete ==="
