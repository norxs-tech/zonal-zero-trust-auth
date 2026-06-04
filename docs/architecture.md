# Architecture — norxs zonal-zero-trust-authenticator

**norxs Technology LLC** | Safety Engineering, Built from the Ground Up.
*(c) 2026 norxs Technology LLC. All rights reserved.*

---

## Table of Contents

1. [Design Philosophy](#1-design-philosophy)
2. [System Context](#2-system-context)
3. [Hardware Deployment Targets](#3-hardware-deployment-targets)
4. [Software Layer Model](#4-software-layer-model)
5. [Module Architecture](#5-module-architecture)
   - 5.1 [CryptoPlatformInterface (PAL)](#51-cryptoplatforminterface-pal)
   - 5.2 [SpdmProtocolEngine (FSM)](#52-spdmprotocolengine-fsm)
   - 5.3 [TokenLifecycleManager (TLM)](#53-tokenlifecyclemanager-tlm)
   - 5.4 [StaticCircularBuffer (LRU)](#54-staticcircularbuffer-lru)
6. [SPDM Handshake — Full Protocol Flow](#6-spdm-handshake--full-protocol-flow)
7. [Cryptographic Design](#7-cryptographic-design)
8. [Memory Architecture](#8-memory-architecture)
9. [Threat Model & Countermeasures](#9-threat-model--countermeasures)
10. [Standards Compliance Matrix](#10-standards-compliance-matrix)
11. [AUTOSAR C++14 Compliance Evidence](#11-autosar-c14-compliance-evidence)
12. [Inter-Module Data Flow](#12-inter-module-data-flow)
13. [Production Integration Guide](#13-production-integration-guide)
14. [Known Limitations of Reference Implementation](#14-known-limitations-of-reference-implementation)

---

## 1. Design Philosophy

The **zonal-zero-trust-authenticator** is built around five non-negotiable principles:

### 1.1 Zero-Heap

Every data structure is a `std::array`, `constexpr`, or stack-local variable. No call to
`new`, `delete`, `malloc`, or `free` exists anywhere in the production code paths.
This is enforced at CI time by a grep-based compliance scan that fails the build on any
match.

**Why:** Dynamic allocation in safety-critical ECU software introduces unbounded execution
time, fragmentation risk, and non-deterministic failure modes that are incompatible with
ISO 26262 ASIL-D certification.

### 1.2 Zero-Exception

No `try`, `catch`, or `throw` in any file. All error conditions are communicated via
return codes (`CryptoStatus`, `SpdmStatus`, `TlmStatus`). Every function marked
`[[nodiscard]]` must have its return code checked by the caller — unchecked status is a
MISRA C++ 0-1-7 violation.

### 1.3 Platform Decoupling

All hardware contact — RNG, hash accelerator, HSE — is isolated behind the
`CryptoPlatformInterface` pure-virtual PAL. The FSM and lifecycle manager carry zero
hardware awareness. A single CMake toolchain switch (`-DCMAKE_TOOLCHAIN_FILE=...`)
selects the correct PAL implementation at link time.

### 1.4 Constant-Time Critical Paths

Every comparison involving secret material (client IDs, session keys, ECC signatures)
uses a `volatile uint8_t` accumulator loop rather than `memcmp` or short-circuit
equality. This prevents timing-based side-channel attacks (ISO/SAE 21434 THREAT-05).

### 1.5 Explicit Sanitisation

Session keys and nonces are zeroed via `volatile` byte-write loops — not `memset` — on
every session termination path (Revoke, Reset, expiry, LRU eviction). This prevents
residual key material from persisting in RAM (UN R155 §7.2.2).

---

## 2. System Context

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         Vehicle E/E Architecture                             │
│                                                                              │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                  │
│   │  Zone Node A  │    │  Zone Node B  │    │  Zone Node C  │                  │
│   │ (Perception) │    │ (Chassis)     │    │ (Body)       │                  │
│   │ Cortex-M7    │    │ Cortex-M7    │    │ Cortex-M7    │                  │
│   └──────┬───────┘    └──────┬───────┘    └──────┬───────┘                  │
│          │ SOME/IP / 1000BASE-T1 Automotive Ethernet                         │
│          └──────────────────┬──────────────────────┘                         │
│                             │                                                │
│   ┌──────────────────────────▼──────────────────────────────────────────┐    │
│   │                    Zonal Gateway ECU                                │    │
│   │              NXP S32G (Cortex-A53 × 4 + Cortex-M7 × 3)            │    │
│   │                                                                     │    │
│   │   ┌──────────────────────────────────────────────────────────────┐ │    │
│   │   │          zonal-zero-trust-authenticator (this repo)          │ │    │
│   │   │                                                              │ │    │
│   │   │  SpdmProtocolEngine[0]  TokenLifecycleManager               │ │    │
│   │   │  SpdmProtocolEngine[1]      ┌──────────────────┐            │ │    │
│   │   │  SpdmProtocolEngine[2]      │  session_table_  │            │ │    │
│   │   │  ...up to 8                 │  [0..7]: slots   │            │ │    │
│   │   │         │                   │  insertion_order_│            │ │    │
│   │   │         │ PAL calls         └──────────────────┘            │ │    │
│   │   │         ▼                                                    │ │    │
│   │   │  CryptoPlatformInterface                                     │ │    │
│   │   │    └─ HseCryptoProvider (NXP S32G HSE, production)          │ │    │
│   │   │    └─ SoftwareCryptoProvider (host CI, test only)           │ │    │
│   │   └──────────────────────────────────────────────────────────────┘ │    │
│   │                                                                     │    │
│   └─────────────────────────────────────────────────────────────────────┘    │
│                             │                                                │
│                    Central Gateway / Cloud VSP                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Hardware Deployment Targets

| Target | SoC | Core | OS | Memory | Use Case |
|--------|-----|------|----|--------|----------|
| **A53-QNX** | NXP S32G274A | Cortex-A53 @ 1.0 GHz | QNX Neutrino 7.1 | DDR4 2 GB | AUTOSAR Adaptive gateway process |
| **A53-Linux** | NXX S32G274A | Cortex-A53 @ 1.0 GHz | Linux 5.15 | DDR4 2 GB | CI pipeline, integration testing |
| **M7-BareMetal** | NXP S32G274A | Cortex-M7 @ 400 MHz | Bare-metal / RTOS | SRAM 512 KB | Zone domain controller |
| **Host-x86** | Any x86-64 | N/A | Linux / macOS | N/A | Developer workstation CI |

### Toolchain Files

```
cmake/Toolchain-A53.cmake   →  aarch64-linux-gnu-g++  -mcpu=cortex-a53
cmake/Toolchain-M7.cmake    →  arm-none-eabi-g++      -mcpu=cortex-m7 -mthumb --specs=nosys.specs
```

The `SoftwareCryptoProvider` is used on **Host** and **A53-Linux** only.
All other targets link `HseCryptoProvider` (NXP HSE firmware v3.x) or
`TrustZoneCryptoProvider` (Arm TrustZone-M for M33-class parts).

---

## 4. Software Layer Model

```
┌───────────────────────────────────────────────────────────────────┐
│  Application Layer                                                │
│  (SOME/IP session manager, IDS agent, OTA update orchestrator)    │
├───────────────────────────────────────────────────────────────────┤
│  Token Lifecycle Layer                                            │
│  TokenLifecycleManager  ←─ RevocationCallback ─→  App            │
│  StaticCircularBuffer<8>   (session table, LRU order)             │
├───────────────────────────────────────────────────────────────────┤
│  Protocol Engine Layer                                            │
│  SpdmProtocolEngine[0..7]  (one per authenticated zone slot)      │
│  State: kUnauthenticated / kChallengeSent / kAuthenticated        │
│         / kRevoked                                                │
├───────────────────────────────────────────────────────────────────┤
│  Platform Abstraction Layer (PAL)                                 │
│  CryptoPlatformInterface  (pure virtual, zero hardware)           │
├────────────────────┬──────────────────────────────────────────────┤
│  SW Crypto (CI)    │  NXP HSE (A53/M7 production)                 │
│  SoftwareCryptoProvider │  HseCryptoProvider                      │
│  LFSR · SHA-256    │  HSE_SRV_ID_GET_RANDOM                       │
│  mock ECC          │  HSE_SRV_ID_ECDSA_VERIFY                     │
│  HMAC-HKDF         │  HSE_SRV_ID_KEY_DERIVE                       │
└────────────────────┴──────────────────────────────────────────────┘
```

---

## 5. Module Architecture

### 5.1 CryptoPlatformInterface (PAL)

**Files:** `include/zzta/CryptoPlatformInterface.hpp`, `src/CryptoPlatformInterface.cpp`

The PAL is a pure-virtual interface with four methods:

| Method | Purpose | Production Backend |
|--------|---------|-------------------|
| `GenerateRandomNonce(Nonce&)` | TRNG/DRBG 256-bit random | HSE `GET_RANDOM` |
| `ComputeSha256(data, len, Sha256Digest&)` | FIPS 180-4 SHA-256 | HSE `HASH_SHA256` |
| `VerifyEccSignature(digest, sig, pubkey)` | ECDSA-P256 verify | HSE `ECDSA_VERIFY` |
| `DeriveSessionKey(nonce, client_id, SessionKey&)` | HKDF-SHA-256 expand | HSE `KEY_DERIVE` |

**Type aliases (all `std::array<uint8_t, N>`):**

```
Nonce          [32]   —  challenge nonce (256-bit)
Sha256Digest   [32]   —  SHA-256 output
CryptoSignature[64]   —  ECC-P256 (r ∥ s), raw bytes
SessionKey     [32]   —  AES-256 session key
EccPublicKey   [33]   —  compressed P-256 point (0x02/03 prefix)
ClientId       [ 8]   —  opaque 64-bit node identifier
```

**SoftwareCryptoProvider** (CI / host only):

- `GenerateRandomNonce`: Galois-LFSR-32 (polynomial `0xB4000000`), seeded at construction.
- `ComputeSha256`: FIPS 180-4 byte-at-a-time with stack-local `W[64]` schedule.
- `VerifyEccSignature`: mock via `SHA-256(digest ∥ salt)` ∥ `SHA-256(salt ∥ digest)`.
- `DeriveSessionKey`: RFC 5869 HMAC-SHA-256 Extract-then-Expand using `kMockMasterSalt`.

The `ZZTA_PRODUCTION_BUILD` preprocessor flag triggers a `static_assert(false)` inside
`CryptoPlatformInterface.cpp` to prevent accidental inclusion in release configurations.

---

### 5.2 SpdmProtocolEngine (FSM)

**Files:** `include/zzta/SpdmProtocolEngine.hpp`, `src/SpdmProtocolEngine.cpp`

One engine instance manages exactly one authenticated zone node slot.
The Zonal Gateway allocates up to `kMaxKnownPeers = 8` engine instances.

#### State Machine

```
                    ProcessAuthRequest()
  kUnauthenticated ──────────────────────► kChallengeSent
       ▲                                        │
       │  Reset()                               │ ProcessAuthResponse()
       │                                        │  [valid ECDSA]
  kRevoked ◄─── Revoke() ──────────────── kAuthenticated
       │
       └─── Reset() ──► kUnauthenticated
```

#### ProcessAuthRequest() — detailed flow

```
1. Guard: state == kUnauthenticated         → else kInvalidState / kAlreadyAuthenticated
2. Version check: request.version == {01,10,00,00}  → else kVersionMismatch
3. Peer table lookup: FindPeerPublicKey(request.client_id)
   → unknown peer → return kSignatureInvalid (no nonce generated, prevents RNG oracle)
4. PAL: GenerateRandomNonce(pending_nonce_)  → kCryptoError on failure
5. pending_client_id_ = request.client_id
6. state_ = kChallengeSent
7. return kOk
```

#### ProcessAuthResponse() — detailed flow

```
1. Guard: state == kChallengeSent
2. Constant-time: response.client_id == pending_client_id_ → Revoke(); kClientIdMismatch
3. FindPeerPublicKey(response.client_id, peer_public_key)
4. ComputeChallengeDigest: PAL.SHA-256(nonce ∥ client_id) → Sha256Digest
5. PAL.VerifyEccSignature(digest, response.signature, peer_public_key)
   → kVerifyFailed → Revoke(); kSignatureInvalid
   → kHwFault    → Revoke(); kCryptoError
6. PAL.DeriveSessionKey(pending_nonce_, response.client_id, derived_key)
7. Populate session_token_out (client_id, session_nonce, session_key)
8. Sanitise derived_key local copy (volatile loop)
9. state_ = kAuthenticated
10. return kOk
```

#### Known-Peer Table

```cpp
struct KnownPeerEntry {
    ClientId     client_id;   // 8-byte node ID
    EccPublicKey public_key;  // 33-byte compressed P-256
};
static constexpr std::size_t kMaxKnownPeers{8U};
```

In production, this table is generated from an OEM-signed X.509 certificate chain
at secure-boot time and placed in write-protected flash. For the reference implementation,
entry [0] uses the `SoftwareCryptoProvider` test key pair.

---

### 5.3 TokenLifecycleManager (TLM)

**Files:** `include/zzta/TokenLifecycleManager.hpp`, `src/TokenLifecycleManager.cpp`

#### Session Table Layout

```
session_table_[0..7]  →  std::array<TokenSlot, 8>  (.bss, zero-alloc)

TokenSlot {
    ClientId   client_id       [ 8]
    SessionKey session_key     [32]
    Nonce      session_nonce   [32]
    uint64_t   issued_at_ms        (8)
    uint64_t   last_seen_ms        (8)
    uint8_t    anomaly_count       (1)
    bool       is_active           (1)
    bool       is_locked_out       (1)
    uint8_t    reserved_[3]        (3)
}
// static_assert(sizeof(TokenSlot) <= 128U) — enforced at compile time
// Total table: 8 × 128 = 1024 bytes maximum
```

#### RegisterToken() — LRU eviction logic

```
1. Validate client_id ≠ all-zero (sentinel check)
2. IsLockedOut(client_id) → kLockedOut
3. FindSlotByClientId(client_id):
   → found & active → ZeroSlotSecrets; is_active=false; Remove from insertion_order_; callback
4. FindFreeSlot(target_idx):
   → not found → insertion_order_.Pop(lru_idx) → ZeroSlotSecrets; callback → reuse lru slot
5. Copy token fields → slot
6. insertion_order_.Push(target_idx)
7. return kOk
```

#### EvaluateTokenExpiry() — UN R155 periodic scan

```
for i in [0..kMaxActiveSessions):
    if slot[i].is_active:
        age = current_time_ms − slot[i].issued_at_ms
        if age > kTokenLifetimeMs (30 000 ms):
            ZeroSlotSecrets(i)
            is_active = false
            Remove(i) from insertion_order_
            NotifyRevocation(client_id)
```

Worst-case execution time is `O(kMaxActiveSessions) = O(8)` — bounded and deterministic.
Caller must invoke this function at a rate ≤ `kTokenLifetimeMs / 2` = every 15 seconds.

#### Anomaly Lockout (THREAT-08)

```
RevokeToken(client_id, is_anomaly=true):
    slot.anomaly_count++
    if anomaly_count >= kMaxAnomalyCount (3):
        slot.is_locked_out = true   ← permanent for this power cycle
    ZeroSlotSecrets; is_active=false; NotifyRevocation
```

---

### 5.4 StaticCircularBuffer (LRU)

**File:** `include/zzta/TokenLifecycleManager.hpp` (template, header-only)

```cpp
template<std::size_t N>
class StaticCircularBuffer {
    std::array<uint8_t, N> buf_;
    std::size_t head_, tail_, count_;
public:
    bool Push(std::size_t idx);     // enqueue slot index
    bool Pop(std::size_t& idx_out); // dequeue oldest slot index (LRU victim)
    void Remove(std::size_t idx);   // O(N) compact — called on explicit revoke
};
```

`Push` / `Pop` are O(1). `Remove` is O(N) — called only on explicit revocation, not
on the periodic expiry hot path.

---

## 6. SPDM Handshake — Full Protocol Flow

```
Zone Node (Peer)                          Zonal Gateway ECU
     │                                          │
     │  SpdmAuthRequest                         │
     │  { client_id, version={01,10,00,00} }    │
     │ ─────────────────────────────────────► │
     │                                          │  ProcessAuthRequest():
     │                                          │  1. version check
     │                                          │  2. peer table lookup
     │                                          │  3. TRNG → nonce[32]
     │                                          │  state → kChallengeSent
     │                                          │
     │  CHALLENGE: nonce[32]                    │
     │ ◄──────────────────────────────────── │
     │                                          │
     │  [Peer computes:]                        │
     │  digest = SHA-256(nonce ∥ client_id)     │
     │  sig = ECDSA-P256(privKey, digest)       │
     │                                          │
     │  SpdmAuthResponse                        │
     │  { client_id, signature[64] }            │
     │ ─────────────────────────────────────► │
     │                                          │  ProcessAuthResponse():
     │                                          │  1. client_id continuity (ct-cmp)
     │                                          │  2. peer public key lookup
     │                                          │  3. digest = SHA-256(nonce ∥ id)
     │                                          │  4. ECDSA-P256 verify
     │                                          │  5. HKDF-SHA-256(nonce, id) → key
     │                                          │  state → kAuthenticated
     │                                          │
     │                                          │  TokenLifecycleManager
     │                                          │    .RegisterToken(token, t_now)
     │                                          │
     │  ← AUTH SUCCESS (application signal) ─  │
     │                                          │
     │  [Subsequent SOME/IP traffic encrypted]  │
     │  [with AES-256-GCM session_key]          │
     │                                          │
     │  [After 30 s / anomaly / IDS alert]      │
     │                                          │  EvaluateTokenExpiry() or RevokeToken()
     │                                          │    → ZeroSlotSecrets
     │                                          │    → RevocationCallback → SpdmEngine.Revoke()
     │  ← RE-AUTH REQUIRED ──────────────────── │
     │                                          │
```

---

## 7. Cryptographic Design

### 7.1 Challenge Nonce

| Property | Value |
|----------|-------|
| Size | 256 bits (32 bytes) |
| Source (production) | NXP HSE `HSE_SRV_ID_GET_RANDOM` (NIST SP 800-90B-compliant TRNG) |
| Source (CI mock) | Galois-LFSR-32 (deterministic, not cryptographically secure) |
| Freshness guarantee | Per-handshake; never reused across sessions |
| Replay protection | Nonce binds the response to this specific challenge instance |

### 7.2 Challenge Digest

```
digest = SHA-256(nonce[32] ∥ client_id[8])
       = SHA-256(40-byte input)
```

Binding both the nonce and the client identity into the signed digest prevents:
- Replay attacks (stale nonce rejected)
- Cross-peer replay (different client_id → different digest)
- Chosen-message attacks (attacker cannot predict nonce)

### 7.3 Signature Scheme

| Property | Value |
|----------|-------|
| Algorithm | ECDSA-P256 (secp256r1 / NIST P-256) |
| Hash | SHA-256 (applied to `nonce ∥ client_id`) |
| Key size | 256-bit private scalar |
| Public key format | Compressed (33 bytes, 0x02/03 prefix + X coordinate) |
| Verification | Constant-time via `volatile` accumulator |

### 7.4 Session Key Derivation (HKDF-SHA-256, RFC 5869)

```
IKM   = session_nonce[32] ∥ client_id[8]     (40 bytes)
Salt  = platform master secret[32]            (OTP fuse / HSE slot 0)
Info  = "zzta-session-v1"                     (15 bytes, ASCII, no NUL)

PRK   = HMAC-SHA-256(Salt, IKM)               — Extract step
OKM   = HMAC-SHA-256(PRK, "" ∥ Info ∥ 0x01)  — Expand step, T(1) only
                                              (32 bytes — one HMAC block)

session_key = OKM[0..31]                      — AES-256-GCM key
```

The session key uniquely identifies this (nonce, client_id) pair. Even if two nodes
share the same platform master secret, their distinct nonces and client IDs produce
orthogonal session keys.

### 7.5 Key Lifecycle

```
Derivation       → SpdmProtocolEngine.ProcessAuthResponse()
Registration     → TokenLifecycleManager.RegisterToken()
Active use       → SOME/IP payload encryption (AES-256-GCM, application layer)
ValidateToken()  → returns key copy on each validated frame
Revocation       → ZeroSlotSecrets() — volatile loop, both key and nonce
Sanitisation     → SanitiseSecretMaterial() — volatile loop on pending nonce
```

---

## 8. Memory Architecture

### 8.1 Static Data (.bss / .data)

| Symbol | Location | Size |
|--------|----------|------|
| `TokenLifecycleManager::session_table_` | `.bss` | 8 × 128 = **1 024 B** |
| `SpdmProtocolEngine` instance (×8) | `.bss` | 8 × ~128 = **~1 024 B** |
| `kSha256K[64]` | `.rodata` | 256 B |
| `kSha256InitHash[8]` | `.rodata` | 32 B |
| `kMockEccPublicKey[33]` | `.rodata` | 33 B |
| `kMockMasterSalt[32]` | `.rodata` | 32 B |
| `kHkdfInfo[15]` | `.rodata` | 15 B |
| Known-peer table (8 entries) | `.rodata` | 8 × 41 = 328 B |

**Total static footprint: ≈ 2 794 B** — well within the 512 KB SRAM of the Cortex-M7 target.

### 8.2 Stack Usage

| Function | Stack (Cortex-M7, -Os) |
|----------|----------------------|
| `Sha256Impl()` | 64 (W[]) + 8 (h[]) + 64 (block[]) = **~256 B** |
| `DeriveSessionKey()` | 2 × 64 (ipad/opad) + 80 (inner_input) = **~256 B** |
| `ProcessAuthResponse()` | 40 (msg[]) + 32 (digest) + 32 (key) = **~128 B** |
| `EvaluateTokenExpiry()` | 8 (expired_id) + loop locals = **~32 B** |

The CI stack-analysis job (`-fstack-usage`) reports these values and fails the build if
any single function exceeds 1 024 bytes of stack on M7.

### 8.3 Heap

**Zero bytes.** No `new`, `delete`, `malloc`, `free`, `std::vector`, `std::map`,
`std::string`, `std::shared_ptr`, or `std::unique_ptr` anywhere in production code.
Verified by CI compliance-scan job.

---

## 9. Threat Model & Countermeasures

The following threats are drawn from the project TARA (ISO/SAE 21434 §15).

| Threat ID | Description | Countermeasure | Implementation |
|-----------|-------------|----------------|---------------|
| **THREAT-01** | Replay of captured SPDM response | Per-handshake 256-bit random nonce | `GenerateRandomNonce()` |
| **THREAT-02** | Forged SPDM response (no key) | ECDSA-P256 signature over `SHA-256(nonce‖id)` | `VerifyEccSignature()` |
| **THREAT-03** | Authentication bypass (state skip) | FSM state guard on every transition | `ProcessAuthRequest/Response()` |
| **THREAT-04** | Session key recovery (memory dump) | Volatile-loop zeroing on all revocation paths | `ZeroSlotSecrets()`, `SanitiseSecretMaterial()` |
| **THREAT-05** | Timing side-channel on signature verify | `volatile uint8_t` accumulator, no early-exit | `VerifyEccSignature()`, `FindSlotByClientId()` |
| **THREAT-06** | Session fixation (static SecOC keys) | HKDF per-session key derivation; 30-s expiry | `DeriveSessionKey()`, `EvaluateTokenExpiry()` |
| **THREAT-07** | RNG oracle via challenge enumeration | Nonce only generated after peer table hit | `ProcessAuthRequest()` — step 3 before step 4 |
| **THREAT-08** | Brute-force authentication | Lockout after 3 anomalies (power-cycle scope) | `anomaly_count`, `is_locked_out` in `TokenSlot` |
| **THREAT-09** | Session token table overflow | LRU eviction via `StaticCircularBuffer` | `RegisterToken()` — LRU path |
| **THREAT-10** | Cross-peer session hijack | Client ID bound into HKDF IKM and signed digest | `ComputeChallengeDigest()` + `DeriveSessionKey()` |

---

## 10. Standards Compliance Matrix

| Requirement | Standard | Clause | How Met |
|-------------|----------|--------|---------|
| Zero dynamic allocation | AUTOSAR C++14 | [A18-1-1] | No `new`/`delete`/`malloc` |
| No exceptions | AUTOSAR C++14 | [A15-0-1] | No `try/catch/throw`; `-fno-exceptions` |
| No RTTI | AUTOSAR C++14 | [A18-9-1] | `-fno-rtti` in all toolchains |
| Return-code checked | MISRA C++ | 0-1-7 | `[[nodiscard]]` on all status-returning methods |
| Bounds-checked arrays | AUTOSAR C++14 | [A26-5-1] | `std::array`, no raw pointer arithmetic |
| Copy/move controlled | AUTOSAR C++14 | [A12-0-1] | Deleted copy/move on all owning types |
| No recursion | ISO 26262 | Part 6 §7.4.7 | No recursive calls anywhere |
| Deterministic timing | ISO 26262 | Part 4 §6.4.6 | All loops bounded at compile time |
| Key erasure on termination | UN R155 | §7.2.2 | `ZeroSlotSecrets()`, `SanitiseSecretMaterial()` |
| Continuous session monitoring | UN R155 | §7.2.2 | `EvaluateTokenExpiry()` |
| Brute-force protection | ISO/SAE 21434 | §15 CM-08 | Anomaly counter + lockout |
| Constant-time secret comparison | ISO/SAE 21434 | §15 CM-05 | `volatile` accumulator pattern |
| TRNG-based nonce | NIST SP 800-90B | §4 | `GenerateRandomNonce()` → HSE |
| ECDSA-P256 signatures | FIPS PUB 186-5 | §6.4 | `VerifyEccSignature()` → HSE |
| SHA-256 digest | FIPS PUB 180-4 | §6.2 | `ComputeSha256()` |
| HKDF-SHA-256 key derivation | RFC 5869 | §2 | `DeriveSessionKey()` |

---

## 11. AUTOSAR C++14 Compliance Evidence

Verified by the CI `compliance-scan` job (`grep` pattern match on all `.cpp` / `.hpp` files
under `src/` and `include/`):

| Pattern | Occurrences | Verdict |
|---------|-------------|---------|
| `try` / `catch` / `throw` | **0** | ✅ |
| `new` / `delete` (excluding `= delete`) | **0** | ✅ |
| `malloc` / `calloc` / `realloc` / `free` | **0** | ✅ |
| `std::vector` | **0** | ✅ |
| `std::map` / `std::unordered_map` | **0** | ✅ |
| `std::string` | **0** | ✅ |
| `std::shared_ptr` / `std::unique_ptr` | **0** | ✅ |
| `std::mutex` / `std::lock_guard` | **0** | ✅ |
| Doxygen `@file` header | **7 / 7 files** | ✅ |
| `#ifndef` include guards | **3 / 3 headers** | ✅ |

---

## 12. Inter-Module Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│  Application / SOME/IP Session Manager                              │
│                                                                     │
│  on_incoming_frame(client_id, payload):                             │
│    status = tlm.ValidateToken(client_id, now_ms, &key)              │
│    if status == kOk:                                                │
│        decrypt_with_aes_gcm(payload, key)                           │
│    else:                                                            │
│        trigger_reauth(client_id)                                    │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │ SpdmSessionToken (on new auth)
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│  TokenLifecycleManager                                              │
│  RegisterToken(token, now_ms)  ←── from SpdmProtocolEngine         │
│  ValidateToken(id, now_ms, &key)  ──► to application               │
│  RevokeToken(id, is_anomaly)   ←── from IDS agent                  │
│  EvaluateTokenExpiry(now_ms)   ←── from 15-second OS timer         │
│  RevocationCallback            ──► SpdmEngine.Revoke() + App       │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │ ProcessAuthRequest / Response
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│  SpdmProtocolEngine[0..7]                                           │
│  ProcessAuthRequest(request)  ←── SOME/IP inbound frame            │
│  GetPendingChallenge()        ──► SOME/IP outbound challenge        │
│  ProcessAuthResponse(resp, &token)  ←── SOME/IP response frame     │
│  Revoke() / Reset()           ←── TLM callback / IDS               │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │ GenerateRandomNonce / ComputeSha256
                                  │ VerifyEccSignature / DeriveSessionKey
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│  CryptoPlatformInterface                                            │
│  └─ HseCryptoProvider        (NXP S32G, production)                │
│  └─ SoftwareCryptoProvider   (host CI, test only)                  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 13. Production Integration Guide

### 13.1 Implementing HseCryptoProvider

Create a new file `src/HseCryptoProvider.cpp` with the following skeleton:

```cpp
#include "zzta/CryptoPlatformInterface.hpp"
#include "hse_host.h"    // NXP HSE host driver header

namespace zzta {

class HseCryptoProvider final : public CryptoPlatformInterface {
public:
    CryptoStatus GenerateRandomNonce(Nonce& nonce_out) noexcept override {
        hseSrvDescriptor_t srv{};
        srv.srvId = HSE_SRV_ID_GET_RANDOM;
        srv.hseSrv.getRandomReq.randomNum    = nonce_out.data();
        srv.hseSrv.getRandomReq.randomNumLen = static_cast<uint32_t>(kNonceLen);
        hseStatus_t st = HSE_Send(MU0_MBX0, &srv);
        return (st == HSE_SRV_RSP_OK) ? CryptoStatus::kOk : CryptoStatus::kHwFault;
    }

    CryptoStatus ComputeSha256(const uint8_t* data, std::size_t len,
                               Sha256Digest& out) noexcept override {
        // HSE_SRV_ID_HASH with HSE_HASH_ALGO_SHA2_256
        // ... (see NXP HSE Firmware Reference Manual §8.6)
        (void)data; (void)len; (void)out;
        return CryptoStatus::kNotSupported; // replace with HSE call
    }

    CryptoStatus VerifyEccSignature(const Sha256Digest& digest,
                                    const CryptoSignature& sig,
                                    const EccPublicKey& pub) noexcept override {
        // HSE_SRV_ID_SIGN with HSE_SIGN_ECDSA and keyHandle from OEM provisioning
        // ... (see NXP HSE Firmware Reference Manual §8.11)
        (void)digest; (void)sig; (void)pub;
        return CryptoStatus::kNotSupported; // replace with HSE call
    }

    CryptoStatus DeriveSessionKey(const Nonce& nonce, const ClientId& id,
                                   SessionKey& key_out) noexcept override {
        // HSE_SRV_ID_KEY_DERIVE with HSE_KDF_ALGO_HKDF_SHA256
        // ... (see NXP HSE Firmware Reference Manual §8.14)
        (void)nonce; (void)id; (void)key_out;
        return CryptoStatus::kNotSupported; // replace with HSE call
    }
};

} // namespace zzta
```

### 13.2 Provisioning the Peer Table

```cpp
// In your application initialisation code:
static constexpr std::array<zzta::KnownPeerEntry, 3U> kPeerTable{{
    // Entry 0: Zone Domain A — Perception node
    {
        .client_id  = {0x01U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U},
        .public_key = { /* 33-byte compressed P-256 from OEM certificate */ }
    },
    // Entry 1: Zone Domain B — Chassis node
    {
        .client_id  = {0x02U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U},
        .public_key = { /* ... */ }
    },
    // ... up to kMaxKnownPeers (8) entries
}};

zzta::HseCryptoProvider crypto_pal{};

zzta::SpdmProtocolEngine engines[3]{
    {crypto_pal, kPeerTable.data(), kPeerTable.size()},
    {crypto_pal, kPeerTable.data(), kPeerTable.size()},
    {crypto_pal, kPeerTable.data(), kPeerTable.size()},
};

zzta::TokenLifecycleManager tlm{&OnRevocationCallback};
```

### 13.3 Wiring the SOME/IP Receive Handler

```cpp
void OnSomeIpAuthRequest(const uint8_t* frame, std::size_t len, std::size_t slot_idx) {
    zzta::SpdmAuthRequest req{};
    std::memcpy(&req, frame, sizeof(req));

    zzta::SpdmStatus st = engines[slot_idx].ProcessAuthRequest(req);
    if (st == zzta::SpdmStatus::kOk) {
        const zzta::Nonce& challenge = engines[slot_idx].GetPendingChallenge();
        SomeIp_Transmit(slot_idx, challenge.data(), challenge.size());
    } else {
        // Log st; possibly increment external anomaly counter
    }
}

void OnSomeIpAuthResponse(const uint8_t* frame, std::size_t len, std::size_t slot_idx) {
    zzta::SpdmAuthResponse resp{};
    std::memcpy(&resp, frame, sizeof(resp));

    zzta::SpdmSessionToken token{};
    zzta::SpdmStatus st = engines[slot_idx].ProcessAuthResponse(resp, token);
    if (st == zzta::SpdmStatus::kOk) {
        tlm.RegisterToken(token, GetMonotonicMs());
    } else {
        // Log st; IDS agent may call tlm.RevokeToken(resp.client_id, true)
    }
}
```

### 13.4 Wiring the Periodic Expiry Timer

```cpp
// 15-second OS timer callback (QNX: timer_create + SIGEV_THREAD):
void OnSessionExpiryTick(void*) {
    tlm.EvaluateTokenExpiry(GetMonotonicMs());
}
```

---

## 14. Known Limitations of Reference Implementation

| Limitation | Scope | Mitigation in Production |
|-----------|-------|--------------------------|
| `SoftwareCryptoProvider` LFSR is not CSPRNG | CI only | Replace with `HseCryptoProvider` |
| Mock ECC verification uses SHA-256 approximation | CI only | Use HSE `ECDSA_VERIFY` service |
| `kMockMasterSalt` is embedded in `.rodata` | CI only | Load from HSE OTP fuse / key slot 0 |
| Single-thread, no mutex on session table | All | Caller serialises; MCU is single-core by design |
| No certificate chain validation | Both | Integrate OEM PKI at `FindPeerPublicKey()` insertion point |
| No SPDM message transport binding | Both | Integrate with SOME/IP SD service discovery layer |
| No SOME/IP SecOC fallback | Both | Legacy SecOC retained as safety net during migration |

---

*norxs Technology LLC — Safety Engineering, Built from the Ground Up.*
*(c) 2026 norxs Technology LLC. All rights reserved. | https://norxs.com*
