#!/usr/bin/env bash
# =============================================================================
# first-push.sh — norxs style guide §13: First Push Command Sequence
#
# Usage:
#   chmod +x first-push.sh
#   GITHUB_TOKEN=ghp_xxx REPO_NAME=zonal-zero-trust-authenticator ./first-push.sh
#
# (c) 2026 norxs Technology LLC. All rights reserved.
# =============================================================================

set -euo pipefail

REPO_NAME="${REPO_NAME:-zonal-zero-trust-authenticator}"
GITHUB_TOKEN="${GITHUB_TOKEN:-YOUR_TOKEN}"
GITHUB_ORG="norxs-tech"

echo "=== norxs First Push: ${REPO_NAME} ==="

# Step 1: Ensure we are inside the project folder
if [ ! -f "CMakeLists.txt" ]; then
  echo "ERROR: Run this script from the project root (where CMakeLists.txt lives)."
  exit 1
fi

# Step 2: Initialize git
git init

# Step 3: .gitattributes is already present — verify
if [ ! -f ".gitattributes" ]; then
  echo "ERROR: .gitattributes missing. Aborting."
  exit 1
fi
echo "✅ .gitattributes present (LF line endings enforced)"

# Step 4: Stage all files
git add .

# Step 5: First commit
git commit -m "feat: initial release — norxs zonal-zero-trust-authenticator v1.0.0

- CryptoPlatformInterface: pure-virtual PAL for TRNG, SHA-256, ECDSA-P256, HKDF
- SoftwareCryptoProvider: deterministic CI mock (LFSR + FIPS 180-4 SHA-256)
- SpdmProtocolEngine: 4-state FSM for SPDM DSP0274 v1.1 Challenge-Response
- TokenLifecycleManager: LRU session table, 30 s expiry, anomaly lockout
- StaticCircularBuffer<N>: zero-alloc O(1) LRU tracking
- 32 GoogleTest cases covering all modules and edge cases
- CMake host + cross-compile (Cortex-A53, Cortex-M7)
- CI: build+test · cross-compile · stack · compliance · doxygen (5 jobs)
- docs/architecture.md: full system design and integration guide
- docs/HARA_zonal_zero_trust.md: ISO 26262-3 hazard analysis
- AUTOSAR C++14 compliance: 0 exceptions, 0 heap, 0 RTTI"

# Step 6: Connect to GitHub
git remote add origin "https://${GITHUB_ORG}:${GITHUB_TOKEN}@github.com/${GITHUB_ORG}/${REPO_NAME}.git"

# Step 7: Set main branch and push
git branch -M main
git push -u origin main

echo ""
echo "=== Push complete ==="
echo "Repository: https://github.com/${GITHUB_ORG}/${REPO_NAME}"
echo ""
echo "Next steps:"
echo "  1. Set GitHub repo description:"
echo "     'AUTOSAR C++14 Zero-Trust SPDM Authentication Engine for Zonal ECUs — ECDSA-P256, HKDF-SHA-256, 30 s session expiry. ISO/SAE 21434 · UN R155 · ISO 26262 ASIL-D'"
echo "  2. Add topics: nxp-s32g iso26262 asil-d functional-safety automotive"
echo "                 autosar cpp14 cortex-a53 qnx someip un-r155 iso21434"
echo "                 cybersecurity hse secoc norxs"
echo "  3. Enable branch protection on main (require PR + CI pass)"
