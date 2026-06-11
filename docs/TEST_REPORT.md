# Verification & Test Report — norxs zonal-zero-trust-authenticator

**Document ID:** ZZTA-VTR-001
**Revision:** 1.0.0
**Date:** 2026-06-11
**Project:** zonal-zero-trust-authenticator v1.0.0
**Related:** ZZTA-TARA-001 (TARA) · ZZTA-HARA-001 (HARA) · ZZTA-RTM-001 (Traceability)
**Author:** norxs-lab
**(c) 2026 norxs Technology LLC. All rights reserved.**

---

## 1. Scope

This report records the verification results for the zonal-zero-trust-authenticator
core library (`zzta_core`) and its GoogleTest verification suite. It covers:

- Dynamic verification: 81-case unit/integration test suite under
  AddressSanitizer + UndefinedBehaviorSanitizer
- Structural coverage measurement (line / branch / function)
- Static verification: AUTOSAR C++14 forbidden-pattern scan, cppcheck,
  Doxygen header compliance
- The same checks run as gated jobs in CI (`.github/workflows/ci.yml`);
  this document is the human-readable evidence summary.

## 2. Verification Environment

| Item | Value |
|------|-------|
| Host OS | Ubuntu 24.04 LTS (x86-64) |
| Compiler (test build) | GCC 13.3.0 |
| CI compilers (gating) | GCC 12, Clang 15 (Ubuntu 22.04 runners) |
| Build system | CMake ≥ 3.20 + Ninja |
| Test framework | GoogleTest v1.14.0 (FetchContent, pinned tag) |
| Sanitizers | ASan + UBSan enabled (`ZZTA_ENABLE_ASAN=ON`, `ZZTA_ENABLE_UBSAN=ON`) |
| Coverage tool | gcovr (gcov, `--exclude-unreachable-branches`) |
| Static analysis | cppcheck (`--enable=all --error-exitcode=1`), clang-tidy (advisory) |

## 3. Test Suite Results

**Result: 81 / 81 PASSED** — zero failures, zero ASan/UBSan diagnostics,
total runtime < 10 ms.

| Test Suite | Cases | Result | Verifies |
|------------|------:|--------|----------|
| `SoftwareCryptoProviderTest` | 16 | ✅ PASS | SHA-256 FIPS 180-4 KATs (incl. multi-block), nonce uniqueness/non-zero, HKDF determinism and key separation per nonce and per client ID, null/zero-length parameter rejection, signature bit-flip rejection |
| `SpdmProtocolEngineTest` | 17 | ✅ PASS | All 4 FSM states and every legal/illegal transition, version gate (DSP0274 v1.1), unknown-peer rejection, client-ID continuity check, session key binding, re-authentication after Reset, null peer table hardening |
| `TokenLifecycleManagerTest` | 20 | ✅ PASS | Token CRUD, duplicate refresh, lazy expiry on access, periodic expiry scan (young vs. stale discrimination), revocation callback firing, 3-strike anomaly lockout, LRU eviction on full table, StaticCircularBuffer push/pop/mid-compaction/empty-pop |
| `SomeIpAdaptorTest` | 17 | ✅ PASS | SD lifecycle hooks (OnPeerOffered / OnAuthRequest / OnAuthResponse / OnSessionTick), malformed-frame rejection (short frame, null payload), unknown-peer rejection, version mismatch, re-offer slot reset, transmit-callback-absent tolerance, end-to-end session activation |
| `FaultInjectionTest` | 4 | ✅ PASS | PAL fault propagation: RNG failure and SHA-256 failure surface as `kCryptoError` without state corruption; revoked keys are zeroized and unrecoverable via Validate |
| `ZztaVersionTest` | 3 | ✅ PASS | Semantic version constants, packed 32-bit version word layout, version string |
| `IntegrationTest` | 4 | ✅ PASS | Two concurrent sessions, cross-session key uniqueness, revocation isolation, full lifecycle: handshake → expiry → re-authentication |

Command of record:

```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DZZTA_BUILD_TESTS=ON -DZZTA_ENABLE_ASAN=ON -DZZTA_ENABLE_UBSAN=ON
cmake --build build --target zzta_tests
ctest --test-dir build --output-on-failure
# [==========] 81 tests from 7 test suites ran.
# [  PASSED  ] 81 tests.
```

## 4. Structural Coverage

Measured with gcovr over production sources only (`src/`, `include/zzta/`),
test and GoogleTest internals excluded. CI gates: **line ≥ 90 %, branch ≥ 85 %**.

| Metric | Measured | Gate | Status |
|--------|---------:|-----:|--------|
| Line coverage | **95.2 %** (531 / 558) | ≥ 90 % | ✅ PASS |
| Branch coverage | **88.8 %** (199 / 224) | ≥ 85 % | ✅ PASS |
| Function coverage | **96.7 %** (58 / 60) | — | ✅ |

Per-file breakdown:

| File | Lines | Covered | Line % |
|------|------:|--------:|-------:|
| `src/CryptoPlatformInterface.cpp` | 133 | 133 | 100 % |
| `src/SpdmProtocolEngine.cpp` | 107 | 103 | 96 % |
| `src/TokenLifecycleManager.cpp` | 133 | 131 | 98 % |
| `src/SomeIpAdaptor.cpp` | 110 | 89 | 80 % |
| `include/zzta/TokenLifecycleManager.hpp` | 67 | 67 | 100 % |
| Other headers (inline) | 8 | 8 | 100 % |

**Uncovered-code disposition (engineering judgement, ISO 26262-6 §9.4.5):**
the residual uncovered lines in `SomeIpAdaptor.cpp` are defensive returns on
PAL/engine error paths that require simultaneous multi-fault injection, plus
slot-exhaustion branches. They are short, single-exit guard clauses with no
side effects. Raising `SomeIpAdaptor` branch coverage via an extended
fault-injection matrix is tracked for the next minor release.

## 5. Static Verification Results

| Check | Tool / Method | Result |
|-------|---------------|--------|
| AUTOSAR forbidden patterns (`try/catch/throw`) | comment-stripped regex scan (`scripts/autosar_scan.sh`) | **0 hits** ✅ |
| Heap usage (`new/delete/malloc/calloc/realloc/free`) | same | **0 hits** ✅ |
| Dynamic containers / smart pointers (`std::vector/map/string/...`) | same | **0 hits** ✅ |
| OS synchronisation (`std::mutex/lock_guard/...`) | same | **0 hits** ✅ |
| cppcheck (`--enable=all`, CERT/MISRA subset, `--error-exitcode=1`) | cppcheck, arm32 platform model | **exit 0** ✅ — 3 documented inline suppressions, all `containerOutOfBounds` false positives on HKDF concatenation buffers (justification comments at each site in `CryptoPlatformInterface.cpp`) |
| Doxygen header compliance (`@file @brief @project @standards` + copyright) | per-file tag check (CI Job 5) | **all files compliant** ✅ |
| clang-tidy (AUTOSAR-aligned check set) | clang-tidy-15, advisory | findings logged, non-gating |

## 6. Cross-Compilation Verification

Both embedded targets build the identical source set with no host-only code paths:

| Target | Toolchain | Flags of note | Result |
|--------|-----------|---------------|--------|
| Cortex-A53 (QNX / Linux) | `aarch64-linux-gnu-g++` | `-fno-exceptions -fno-rtti -Os` | ✅ builds in CI Job 2 |
| Cortex-M7 (bare-metal) | `arm-none-eabi-g++` + newlib | `-fstack-usage`, nano.specs | ✅ builds in CI Job 2; stack analysis in CI Job 3 |

Stack budget gate (CI Job 3): **no function may exceed 1024 B** of static
stack — enforced from GCC `.su` stack-usage reports on the M7 build.

## 7. Requirements & Threat Traceability

Full threat → countermeasure → implementation → test-case mapping is maintained
in [`docs/TRACEABILITY.md`](TRACEABILITY.md) (ZZTA-RTM-001). Summary: all 5
TARA threats with risk treatment "reduce" and all 3 UN R155 §7.2.2 derived
requirements (CS.14–CS.16) trace to at least one passing test case.

## 8. Conclusion

The zonal-zero-trust-authenticator v1.0.0 core library passes all dynamic and
static verification gates defined for this release. Residual items
(SomeIpAdaptor fault-matrix coverage extension) are documented in §4 and
tracked for the next release. The reference implementation is fit for its
declared purpose: evaluation, education, and demonstration of norxs
engineering practice. Production deployment additionally requires a
hardware-backed `CryptoPlatformInterface` provider and the commercial safety
and cybersecurity evidence packages described in the README.

---

*(c) 2026 norxs Technology LLC. All rights reserved.*
