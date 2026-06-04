# Changelog

All notable changes to the **norxs zonal-zero-trust-authenticator** are documented here.
This project follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

*(Changes staged for the next release go here)*

---

## [1.0.0] — 2026-06-02

### Initial public release — norxs Technology LLC

This release delivers the foundational three-module core of the zonal-zero-trust-authenticator
framework: a platform-agnostic SPDM Challenge-Response authentication engine for Zonal ECUs
over SOME/IP, completely eliminating the vulnerability of static symmetric keys used in
traditional SecOC. All modules are implemented in zero-heap, zero-exception AUTOSAR C++14
and are verified by a 32-case GoogleTest suite with full state-transition coverage.

### Added — CryptoPlatformInterface

#### `CryptoPlatformInterface` — Cryptographic Platform Abstraction Layer (PAL)
- Pure-virtual abstract interface decoupling all crypto from OS and hardware
- Statically-sized `std::array` DTOs: `Nonce` (32B), `Sha256Digest` (32B), `CryptoSignature` (64B), `SessionKey` (32B), `EccPublicKey` (33B), `ClientId` (8B)
- `[[nodiscard]]` `CryptoStatus` error code on all four PAL operations
- Compile-time policy constants in `.rodata`: `kNonceLen`, `kSha256DigestLen`, `kEccSignatureLen`, `kSessionKeyLen`
- ISO/SAE 21434 §10.4.1 traceability: `CAL_CRYPTO_IF`

#### `SoftwareCryptoProvider` — Deterministic Software Mock
- FIPS PUB 180-4 SHA-256 implementation (no heap, stack-local W[64] message schedule)
- Galois LFSR-32 PRNG for nonce generation (primitive polynomial 0xB4000000, maximal-length)
- HMAC-SHA-256 HKDF-expand (RFC 5869) for session key derivation
- Constant-time ECC mock using volatile accumulator comparison to prevent timing oracle attacks
- Compile-time `static_assert` production-build guard — blocks linkage into ASIL-D release

### Added — SpdmProtocolEngine

#### `SpdmProtocolEngine` — SPDM v1.1 Zero-Trust Handshake State Machine
- Four-state FSM: `kUnauthenticated → kChallengeSent → kAuthenticated → kRevoked`
- `ProcessAuthRequest()`: version gate, peer table lookup (constant-time), 256-bit nonce generation
- `ProcessAuthResponse()`: client ID continuity check, ECC-P256 signature verification, HKDF key derivation
- `Revoke()` / `Reset()`: volatile byte-write secret sanitisation on all exit paths
- Constant-time client ID comparison in `FindPeerPublicKey()` to prevent enumeration attacks (THREAT-07)
- Compile-time `.rodata` peer public key table (`KnownPeerEntry`, max 8 entries)
- DMTF DSP0274 v1.1 version check: `{0x01, 0x10, 0x00, 0x00}`
- ISO/SAE 21434 §10.4.2 traceability: `CAL_SPDM_ENGINE`

### Added — TokenLifecycleManager

#### `TokenLifecycleManager` — Zero-Heap Session Lifecycle Governance
- Fixed-capacity session table: `std::array<TokenSlot, kMaxActiveSessions>` (8 slots, 128B/slot)
- `StaticCircularBuffer<N>`: zero-allocation FIFO for LRU slot eviction with O(1) Push/Pop
- `RegisterToken()`: duplicate detection, locked-out client rejection, LRU eviction on full table
- `ValidateToken()`: lazy expiry on access, optional session key copy-out
- `RevokeToken()`: anomaly counter increment, permanent lockout after `kMaxAnomalyCount` (3) failures
- `EvaluateTokenExpiry()`: O(kMaxActiveSessions) bounded periodic scan — UN R155 §7.2.2 compliance
- `RevocationCallback` function-pointer notification: zero dynamic dispatch overhead
- 30-second compile-time token lifetime (`kTokenLifetimeMs`) with `static_assert` minimum bound
- ISO/SAE 21434 §10.4.3 traceability: `CAL_TLM` / UN R155 CS.14

### Added — Build System & CI

- CMake 3.20+ build system with `ZZTA_BUILD_TESTS`, `ZZTA_PRODUCTION_BUILD`, `ZZTA_ENABLE_ASAN`, `ZZTA_ENABLE_UBSAN` options
- `cmake/Toolchain-A53.cmake`: Cortex-A53/AArch64 with `-fno-exceptions -fno-rtti -Os`
- `cmake/Toolchain-M7.cmake`: Cortex-M7 bare-metal `arm-none-eabi` with `-fstack-usage`, nano.specs
- 5-job CI pipeline: build-and-test (GCC + Clang), cross-compile (A53 + M7), stack-analysis, compliance-scan, doxygen-check
- AUTOSAR compliance scan: grep-based, fails CI on any `try/catch/throw`, `new/malloc`, `std::vector/map/string/shared_ptr/mutex`
- GoogleTest v1.14.0 via FetchContent: 32 test cases covering all nominal and error-injection paths

---

*(c) 2026 norxs Technology LLC. All rights reserved.*
