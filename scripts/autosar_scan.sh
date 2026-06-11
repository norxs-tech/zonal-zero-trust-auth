#!/usr/bin/env bash
# =============================================================================
# scripts/autosar_scan.sh — AUTOSAR C++14 Forbidden Pattern Scan (local runner)
#
# norxs Technology LLC | (c) 2026 | https://norxs.com
#
# This script is the local equivalent of the "AUTOSAR C++14 Compliance" CI job
# (.github/workflows/ci.yml — Job 4). It scans production sources (src/ and
# include/zzta/) for patterns forbidden by the project's AUTOSAR C++14 policy
# and exits non-zero on any hit.
#
# The former `cmake --build . --target compliance` custom target was removed
# because its inline `$(...)` shell substitutions broke the Ninja generator
# (unescaped `$` in build.ninja). Run this script instead:
#
#   ./scripts/autosar_scan.sh
#
# Forbidden patterns:
#   1. try / catch / throw                      (zero-exception mandate)
#   2. new / delete / malloc / calloc / realloc / free   (zero-heap mandate)
#   3. std::vector / map / list / string / smart pointers (dynamic containers)
#   4. std::mutex / lock_guard / unique_lock    (no OS synchronisation deps)
#
# Comments are stripped BEFORE scanning so English words inside Doxygen
# comments ("free slot", "new handshake", "lock-free") are not miscounted.
# =============================================================================

# set -e is intentionally NOT used: `grep` exits 1 on zero matches, which is
# the PASSING case here and must not abort the script.
set -u
cd "$(dirname "$0")/.."

echo "=== AUTOSAR C++14 Forbidden Pattern Scan ==="
FAIL=0

strip_comments() {
  cat src/*.cpp include/zzta/*.hpp 2>/dev/null \
    | perl -0777 -pe 's{/\*.*?\*/}{}gs' \
    | sed -e 's://.*$::'
}

scan() {  # $1 = regex, $2 = human label
  local count
  count=$(strip_comments | grep -E "$1" | wc -l)
  echo "  $2: $count"
  [ "$count" -gt 0 ] && FAIL=1 || true
}

scan '\b(try|catch|throw)\b' \
     "try / catch / throw"
scan '(\bnew\b[[:space:]]+[A-Za-z_]|\bdelete\b[[:space:]]|\b(malloc|free|calloc|realloc)[[:space:]]*\()' \
     "new / delete / malloc / free"
scan 'std::(vector|map|list|string|shared_ptr|unique_ptr|deque|forward_list)' \
     "std::vector / map / string / smart pointers"
scan 'std::(mutex|lock_guard|unique_lock|recursive_mutex)' \
     "std::mutex / lock_guard"

if [ "$FAIL" -ne 0 ]; then
  echo ""
  echo "COMPLIANCE FAILURE: Forbidden patterns detected."
  exit 1
fi

echo ""
echo "All checks PASSED. AUTOSAR C++14 compliant."
