# norxs zonal-zero-trust-authenticator
### Zero-Trust SPDM Authentication Engine for Next-Generation Zonal ECUs over SOME/IP

**norxs Technology LLC** | Safety Engineering, Built from the Ground Up.

[![CI](https://github.com/norxs-tech/zonal-zero-trust-authenticator/actions/workflows/ci.yml/badge.svg)](https://github.com/norxs-tech/zonal-zero-trust-authenticator/actions)
[![License](https://img.shields.io/badge/license-norxs%20RI%20v1.0-blue)](LICENSE)
[![Standard](https://img.shields.io/badge/standard-ISO%2FSAE%2021434-green)]()
[![Safety](https://img.shields.io/badge/safety-ISO%2026262%20ASIL--D-red)]()
[![AUTOSAR](https://img.shields.io/badge/AUTOSAR-C%2B%2B14-orange)]()
[![UN R155](https://img.shields.io/badge/UN%20R155-Compliant-brightgreen)]()
[![OpenChain](https://img.shields.io/badge/OpenChain-ISO%2FIEC%205230%20%C2%B7%2018974-blue)](docs/COMPLIANCE.md)
[![NIST CSF](https://img.shields.io/badge/NIST%20CSF-Aligned-blueviolet)](docs/COMPLIANCE.md)
[![SBOM](https://img.shields.io/badge/SBOM-SPDX%202.3-informational)](sbom/zzta-1.0.0.spdx.json)

---

## What This Is

The **zonal-zero-trust-authenticator** is a production-grade, zero-heap C++14 framework
that implements a Zero-Trust Continuous Verification model for next-generation Zonal ECU
architectures. It replaces the static symmetric keys of traditional SecOC with a full
SPDM DSP0274 v1.1 Challenge-Response handshake, HKDF-SHA-256 session key derivation,
and a UN R155-mandated periodic session expiry engine — all without a single byte of
heap allocation, exception, or OS dependency. The core logic is decoupled from all
hardware and OS specifics through a clean Platform Abstraction Layer (PAL), enabling
identical source files to compile for Cortex-A53/QNX, Cortex-A53/Linux, and
Cortex-M7 bare-metal with only a CMake toolchain switch.

**This is the software we build for our clients — shown here as a reference.**

---

## System Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         Zonal Gateway ECU                                    │
│                    (NXP S32G / Cortex-A53 + Cortex-M7)                      │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐   │
│  │                     SOME/IP Transport Layer                           │   │
│  └────────────────────────────┬──────────────────────────────────────────┘   │
│                               │  Raw frames (untrusted peer messages)        │
│  ┌────────────────────────────▼──────────────────────────────────────────┐   │
│  │               SpdmProtocolEngine  (one per zone node slot)            │   │
│  │                                                                       │   │
│  │  kUnauthenticated ──► kChallengeSent ──► kAuthenticated               │   │
│  │        ▲                                        │                    │   │
│  │        └──────── Revoke() / Reset() ◄───────────┘                    │   │
│  │                           │                                           │   │
│  │  ProcessAuthRequest()     │  Nonce generated via PAL                  │   │
│  │  ProcessAuthResponse()    │  Signature verified via PAL               │   │
│  │                           │  Session key derived via PAL              │   │
│  └────────────────────────────┼──────────────────────────────────────────┘   │
│                               │  SpdmSessionToken                            │
│  ┌────────────────────────────▼──────────────────────────────────────────┐   │
│  │                  TokenLifecycleManager                                │   │
│  │                                                                       │   │
│  │  std::array<TokenSlot, 8>  +  StaticCircularBuffer<8> (LRU)          │   │
│  │                                                                       │   │
│  │  RegisterToken()     ValidateToken()     RevokeToken()                │   │
│  │  EvaluateTokenExpiry() ◄── periodic tick (≤ 15 s interval)           │   │
│  │                                    UN R155 §7.2.2 CS.14              │   │
│  └────────────────────────────┬──────────────────────────────────────────┘   │
│                               │  RevocationCallback                          │
│  ┌────────────────────────────▼──────────────────────────────────────────┐   │
│  │             CryptoPlatformInterface  (PAL — pure virtual)             │   │
│  │                                                                       │   │
│  │  GenerateRandomNonce()   ComputeSha256()                              │   │
│  │  VerifyEccSignature()    DeriveSessionKey()                           │   │
│  │                                                                       │   │
│  │  ┌─────────────────────┐    ┌──────────────────────┐                 │   │
│  │  │ SoftwareCryptoProvider│   │  HseCryptoProvider   │                 │   │
│  │  │  (CI / host testing) │   │  (NXP HSE fw v3.x)   │                 │   │
│  │  │  LFSR-32 · SHA-256  │   │  TRNG · HSE-SHA256   │                 │   │
│  │  │  HMAC-HKDF mock     │   │  HSE-ECC · HSE-KDF   │                 │   │
│  │  └─────────────────────┘   └──────────────────────┘                 │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  Memory model: zero heap · std::array · constexpr · .rodata keys            │
│  Exception model: zero try/catch/throw · CryptoStatus / SpdmStatus return   │
└──────────────────────────────────────────────────────────────────────────────┘

Zone Node Peers (Cortex-M7 Zone Controllers)
  │
  └── SOME/IP ──► SpdmAuthRequest  ──► Zonal Gateway
                  ◄── Nonce challenge
                  SpdmAuthResponse (ECC-P256 signature) ──►
                  ◄── Session active (AES-256-GCM protected traffic)
```

---

## Module Inventory

| Module | Files | Purpose | Standard |
|--------|-------|---------|----------|
| **CryptoPlatformInterface** | `CryptoPlatformInterface.hpp/.cpp` | Pure-virtual PAL for all crypto primitives; SoftwareCryptoProvider mock | ISO/SAE 21434 §10.4.1 |
| **SpdmProtocolEngine** | `SpdmProtocolEngine.hpp/.cpp` | SPDM v1.1 challenge-response FSM; 4-state zero-alloc state machine | DMTF DSP0274, ISO/SAE 21434 §10.4.2 |
| **TokenLifecycleManager** | `TokenLifecycleManager.hpp/.cpp` | Session token table, LRU eviction, periodic expiry, brute-force lockout | UN R155 §7.2.2, ISO/SAE 21434 §10.4.3 |
| **StaticCircularBuffer** | `TokenLifecycleManager.hpp` | Zero-alloc SPSC ring buffer for slot LRU ordering | AUTOSAR C++14 |
| **SomeIpAdaptor** | `SomeIpAdaptor.hpp/.cpp` | SOME/IP SD lifecycle integration: peer offer, SPDM frame dispatch, session tick; Zero-Trust frame gating | AUTOSAR SWS_SD / SWS_SomeIpTp, UN R155 CS.14 |
| **ZztaVersion** | `ZztaVersion.hpp` | AUTOSAR-style SW version constants, packed version word, BSW compatibility check | AUTOSAR SWS_BSWGeneral §7.3 |

---

## Key Algorithms

### 1. SPDM Challenge-Response (`SpdmProtocolEngine`)

```
Zonal Gateway                           Zone Node Peer
      │                                       │
      │◄── SpdmAuthRequest(client_id, v1.1) ──┤
      │                                       │
      │    nonce = TRNG(256 bits)             │
      │──── nonce ─────────────────────────►  │
      │                                       │
      │                        digest = SHA-256(nonce ∥ client_id)
      │                        sig    = ECDSA-P256(digest, privKey)
      │                                       │
      │◄── SpdmAuthResponse(client_id, sig) ──┤
      │                                       │
      │    verify ECDSA-P256(digest, sig, pubKey[client_id])
      │    session_key = HKDF-SHA256(nonce, client_id)
      │    → TokenLifecycleManager.RegisterToken()
      │                                       │
      │    AES-256-GCM protected SOME/IP ────►│
```

### 2. HKDF-SHA-256 Session Key Derivation (RFC 5869)

```
IKM  = nonce (256 bit) ∥ client_id (64 bit)
Salt = Platform Master Secret (OTP fuse / HSE key slot 0)
Info = "zzta-session-v1" (ASCII, 15 bytes)

PRK    = HMAC-SHA256(Salt, IKM)           [Extract]
OKM    = HMAC-SHA256(PRK, "" ∥ Info ∥ 1) [Expand, T(1) only — 256 bit output]

session_key = OKM  →  AES-256-GCM key for SOME/IP payload
```

### 3. Continuous Session Monitoring (UN R155 §7.2.2)

```
EvaluateTokenExpiry(current_time_ms):          // Called every ≤ 15 s
  for each active TokenSlot:
    age = current_time_ms - slot.issued_at_ms
    if age > kTokenLifetimeMs (30 s):
      ZeroSlotSecrets(slot)                     // volatile byte-write loop
      slot.is_active = false
      RevocationCallback(slot.client_id)        // forces SOME/IP channel teardown
      → SpdmProtocolEngine.Reset()             // re-auth required
```

### 4. Brute-Force Lockout (ISO/SAE 21434 THREAT-08)

```
RevokeToken(client_id, is_anomaly=true):
  slot.anomaly_count++
  if slot.anomaly_count >= kMaxAnomalyCount (3):
    slot.is_locked_out = true
    → RegisterToken() returns kLockedOut for this client_id
    → Permanent block until ECU power cycle
```

---

## Compliance

### AUTOSAR C++14 Compliance

| Check | Result |
|-------|--------|
| `try` / `catch` / `throw` | **0** |
| `new` / `delete` / `malloc` / `free` | **0** |
| `std::vector` / `std::map` / `std::string` | **0** |
| `std::shared_ptr` / `std::unique_ptr` | **0** |
| `std::mutex` / `lock_guard` | **0** |
| Heap allocation | **0** |
| RTTI (`dynamic_cast`, `typeid`) | **0** |
| Virtual functions in interface | Only `CryptoPlatformInterface` |

### ISO/SAE 21434 Traceability

| Threat | ID | Countermeasure | Implementation |
|--------|-----|---------------|---------------|
| Authentication Bypass | THREAT-03 | SPDM Challenge-Response | `SpdmProtocolEngine` FSM guards |
| Replay Attack | THREAT-04 | Per-session random nonce (256-bit) | `GenerateRandomNonce()` |
| Timing Side-Channel | THREAT-05 | Constant-time volatile accumulator | All comparison paths |
| Key Exhaustion / Brute Force | THREAT-08 | 3-strike anomaly lockout | `TokenLifecycleManager` |
| Stale Session Exploitation | THREAT-09 | 30 s token expiry + periodic scan | `EvaluateTokenExpiry()` |

### UN R155 §7.2.2 Compliance

| Requirement | Status | Implementation |
|------------|--------|---------------|
| CS.14 — Continuous session monitoring | ✅ | `EvaluateTokenExpiry()` — O(N) bounded |
| CS.15 — Cryptographic agility | ✅ | PAL interface — swap provider without changing FSM |
| CS.16 — Key material erasure | ✅ | `ZeroSlotSecrets()` volatile loop on all revocation paths |

### Supply Chain & Open Source Compliance — OpenChain ISO/IEC 5230 · 18974 · NIST CSF

Full requirement-by-requirement mapping in [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md) (ZZTA-CMP-001).

| Artifact | Standard | Location |
|----------|----------|----------|
| SPDX 2.3 Software Bill of Materials | ISO/IEC 5230 §3.2.1 | [`sbom/zzta-1.0.0.spdx.json`](sbom/zzta-1.0.0.spdx.json) |
| Third-party component inventory + FOSS contact | ISO/IEC 5230 §3.3.1 / §3.1.4 | [`NOTICE`](NOTICE) |
| Vulnerability disclosure policy & response SLAs | ISO/IEC 18974 §3.1.4 | [`SECURITY.md`](SECURITY.md) |
| Commit-hash-pinned dependencies | ISO/IEC 18974 §3.3 / NIST CSF ID.SC | `CMakeLists.txt` (GoogleTest pin) |
| NIST CSF function mapping (Identify→Recover) | NIST CSF | [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md) §4 |

The production library `zzta_core` has **zero third-party dependencies** — the
license-obligation and known-vulnerability surface is empty by construction.
GoogleTest is a build-time test dependency only, pinned by immutable commit hash.

---

## Verification Evidence

Full results in [`docs/TEST_REPORT.md`](docs/TEST_REPORT.md) (ZZTA-VTR-001);
threat-to-test mapping in [`docs/TRACEABILITY.md`](docs/TRACEABILITY.md) (ZZTA-RTM-001).

| Verification Activity | Result |
|----------------------|--------|
| Unit + integration tests (GoogleTest, ASan + UBSan) | **81 / 81 PASSED** — 7 suites |
| Line coverage (gcovr, production sources only) | **95.2 %** (gate ≥ 90 %) |
| Branch coverage | **88.8 %** (gate ≥ 85 %) |
| Function coverage | **96.7 %** |
| AUTOSAR forbidden-pattern scan | **0 violations** |
| cppcheck (`--enable=all`, `--error-exitcode=1`) | **PASS** (3 documented FP suppressions) |
| Doxygen header compliance | **PASS** — all files |
| Cross-compile: Cortex-A53 + Cortex-M7 | **PASS** |
| Cortex-M7 stack budget (≤ 1024 B / function) | **PASS** |

Test suite breakdown:

| Suite | Cases | Focus |
|-------|------:|-------|
| `SoftwareCryptoProviderTest` | 16 | SHA-256 FIPS 180-4 KATs, nonce quality, HKDF key separation |
| `SpdmProtocolEngineTest` | 17 | FSM transition matrix, version gate, signature paths, re-auth |
| `TokenLifecycleManagerTest` | 20 | Token CRUD, expiry, lockout, LRU eviction, ring buffer |
| `SomeIpAdaptorTest` | 17 | SD hooks, malformed-frame rejection, Zero-Trust gating |
| `FaultInjectionTest` | 4 | PAL fault propagation, key zeroization after revoke |
| `ZztaVersionTest` | 3 | Version constants and packed word layout |
| `IntegrationTest` | 4 | Multi-session, key uniqueness, full handshake→expire→re-auth cycle |

---

## Build Instructions

### Prerequisites

- CMake ≥ 3.20
- C++14-capable compiler: GCC ≥ 10, Clang ≥ 12
- For cross-compile targets: `aarch64-linux-gnu-g++` (A53), `arm-none-eabi-g++` (M7)

### Host (CI / unit tests)

```bash
cmake -B build \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DZZTA_BUILD_TESTS=ON \
  -DZZTA_ENABLE_ASAN=ON \
  -DZZTA_ENABLE_UBSAN=ON

cmake --build build --target zzta_tests
ctest --test-dir build --output-on-failure
```

### Cortex-A53 (QNX / Linux)

```bash
cmake -B build-a53 \
  -DCMAKE_TOOLCHAIN_FILE=cmake/Toolchain-A53.cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DZZTA_BUILD_TESTS=OFF

cmake --build build-a53 --target zzta_core
```

### Cortex-M7 (bare-metal)

```bash
cmake -B build-m7 \
  -DCMAKE_TOOLCHAIN_FILE=cmake/Toolchain-M7.cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DZZTA_BUILD_TESTS=OFF

cmake --build build-m7 --target zzta_core
```

### AUTOSAR Compliance Scan

```bash
./scripts/autosar_scan.sh
```

The same scan runs as a gating CI job (Job 4). The former
`cmake --build . --target compliance` custom target was removed because its
inline shell substitutions broke the Ninja generator; the standalone script
above is the local runner of record.

---

## Repository Structure

```
zonal-zero-trust-authenticator/
├── include/zzta/
│   ├── CryptoPlatformInterface.hpp    PAL interface + SoftwareCryptoProvider
│   ├── SpdmProtocolEngine.hpp         SPDM FSM + frame DTOs
│   ├── TokenLifecycleManager.hpp      Session table + StaticCircularBuffer
│   ├── SomeIpAdaptor.hpp              SOME/IP SD lifecycle integration hooks
│   └── ZztaVersion.hpp                AUTOSAR-style version constants
├── src/
│   ├── CryptoPlatformInterface.cpp    SHA-256, LFSR, HKDF, mock ECC
│   ├── SpdmProtocolEngine.cpp         FSM transitions, secret sanitisation
│   ├── TokenLifecycleManager.cpp      Token CRUD, expiry scan, lockout
│   └── SomeIpAdaptor.cpp              Frame validation, slot pool, Zero-Trust gating
├── tests/
│   └── test_zzta_core.cpp             81-case GoogleTest suite (7 suites, all modules)
├── docs/
│   ├── architecture.md                Deep-dive: threat model, data flows
│   ├── TARA.md                        ISO/SAE 21434 §15 threat analysis (ZZTA-TARA-001)
│   ├── HARA_zonal_zero_trust.md       ISO 26262-3 hazard analysis (ZZTA-HARA-001)
│   ├── TEST_REPORT.md                 Verification & test report (ZZTA-VTR-001)
│   ├── TRACEABILITY.md                Threat → code → test matrix (ZZTA-RTM-001)
│   └── COMPLIANCE.md                  ISO/IEC 5230 · 18974 · NIST CSF mapping (ZZTA-CMP-001)
├── cmake/
│   ├── Toolchain-A53.cmake            AArch64 cross-compile (QNX / Linux)
│   ├── Toolchain-M7.cmake             ARM Cortex-M7 bare-metal
│   └── zzta-config.cmake              CMake package config for find_package(zzta)
├── sbom/
│   └── zzta-1.0.0.spdx.json           SPDX 2.3 Software Bill of Materials
├── scripts/
│   └── autosar_scan.sh                Local AUTOSAR forbidden-pattern scan
├── .github/
│   ├── workflows/ci.yml               7-job CI pipeline
│   ├── ISSUE_TEMPLATE/bug_report.md
│   └── PULL_REQUEST_TEMPLATE.md
├── .clang-tidy                        AUTOSAR-aligned clang-tidy check set
├── CMakeLists.txt
├── LICENSE
├── NOTICE                             Third-party inventory + OSS compliance contact
├── SECURITY.md                        Vulnerability disclosure (ISO/IEC 18974-aligned)
├── CHANGELOG.md
├── CONTRIBUTING.md
└── README.md
```

---

## Commercial Licensing & Services

This reference implementation is published under the
**norxs Reference Implementation License v1.0**.
Commercial use requires a separate license agreement.

**norxs Technology LLC** offers:
- Full production source rights for ASIL-D deployment
- ISO 26262 safety evidence package (FMEA, FTA, DFA)
- UN R155 / ISO 21434 cybersecurity artifact package (TARA, STRIDE, penetration test report)
- HseCryptoProvider — production implementation for NXP HSE firmware v3.x (S32G, S32K3)
- TrustZoneCryptoProvider — production implementation for Arm TrustZone-M (Cortex-M33)
- ASPICE process documentation
- Long-term engineering support and maintenance

**Contact:** https://norxs.com

---

## Standards

AUTOSAR C++14 · ISO/SAE 21434 · UN R155 · ISO 26262 ASIL-D · DMTF DSP0274 v1.1 · RFC 5869 · FIPS PUB 180-4 · OpenChain ISO/IEC 5230 · ISO/IEC 18974 · NIST CSF · SPDX (ISO/IEC 5962)

---

*(c) 2026 norxs Technology LLC. All rights reserved.*
