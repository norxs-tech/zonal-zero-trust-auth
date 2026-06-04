# norxs zonal-zero-trust-authenticator
### Zero-Trust SPDM Authentication Engine for Next-Generation Zonal ECUs over SOME/IP

**norxs Technology LLC** | Safety Engineering, Built from the Ground Up.

[![CI](https://github.com/norxs-tech/zonal-zero-trust-authenticator/actions/workflows/ci.yml/badge.svg)](https://github.com/norxs-tech/zonal-zero-trust-authenticator/actions)
[![License](https://img.shields.io/badge/license-norxs%20RI%20v1.0-blue)](LICENSE)
[![Standard](https://img.shields.io/badge/standard-ISO%2FSAE%2021434-green)]()
[![Safety](https://img.shields.io/badge/safety-ISO%2026262%20ASIL--D-red)]()
[![AUTOSAR](https://img.shields.io/badge/AUTOSAR-C%2B%2B14-orange)]()
[![UN R155](https://img.shields.io/badge/UN%20R155-Compliant-brightgreen)]()

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
cmake --build build --target compliance
```

---

## Repository Structure

```
zonal-zero-trust-authenticator/
├── include/zzta/
│   ├── CryptoPlatformInterface.hpp    PAL interface + SoftwareCryptoProvider
│   ├── SpdmProtocolEngine.hpp         SPDM FSM + frame DTOs
│   └── TokenLifecycleManager.hpp      Session table + StaticCircularBuffer
├── src/
│   ├── CryptoPlatformInterface.cpp    SHA-256, LFSR, HKDF, mock ECC
│   ├── SpdmProtocolEngine.cpp         FSM transitions, secret sanitisation
│   └── TokenLifecycleManager.cpp      Token CRUD, expiry scan, lockout
├── tests/
│   └── test_zzta_core.cpp             32-case GoogleTest suite (all modules)
├── docs/
│   └── architecture.md                Deep-dive: threat model, data flows
├── cmake/
│   ├── Toolchain-A53.cmake            AArch64 cross-compile (QNX / Linux)
│   └── Toolchain-M7.cmake             ARM Cortex-M7 bare-metal
├── .github/
│   ├── workflows/ci.yml               5-job CI pipeline
│   ├── ISSUE_TEMPLATE/bug_report.md
│   └── PULL_REQUEST_TEMPLATE.md
├── CMakeLists.txt
├── LICENSE
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

AUTOSAR C++14 · ISO/SAE 21434 · UN R155 · ISO 26262 ASIL-D · DMTF DSP0274 v1.1 · RFC 5869 · FIPS PUB 180-4

---

*(c) 2026 norxs Technology LLC. All rights reserved.*
