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
and are verified by an 81-case GoogleTest suite (7 suites) with full state-transition,
fault-injection, and integration coverage — measured at 95.2 % line / 88.8 % branch
coverage over production sources.

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

### Added — SomeIpAdaptor

#### `SomeIpAdaptor` — SOME/IP Transport Integration Layer
- Pool of up to `kMaxZoneSlots` `SpdmProtocolEngine` instances + one shared `TokenLifecycleManager`
- Four SD lifecycle hooks: `OnPeerOffered()`, `OnAuthRequest()`, `OnAuthResponse()`, `OnSessionTick()`
- Bounds-checked SPDM frame validation: short-frame, null-payload, unknown-peer, and version-mismatch rejection with distinct status codes
- Zero-Trust frame gating: `IsSessionActive()` must report an authenticated live token before any application frame is forwarded
- Re-offer of a known peer resets the slot and forces re-authentication
- 17 dedicated test cases (`SomeIpAdaptorTest`)

### Added — ZztaVersion

#### `ZztaVersion.hpp` — AUTOSAR-Style Version Identification
- `kSwMajorVersion` / `kSwMinorVersion` / `kSwPatchVersion` constants (SemVer 2.0)
- Packed 32-bit version word for single-register BSW compatibility checks (AUTOSAR SWS_BSWGeneral §7.3)
- Vendor ID / module ID constants in the AUTOSAR private range

### Added — Verification & Security Documentation

- `docs/TEST_REPORT.md` (ZZTA-VTR-001): full verification report — 81/81 tests passed under ASan + UBSan, per-file coverage table, static-analysis results, uncovered-code disposition
- `docs/TRACEABILITY.md` (ZZTA-RTM-001): bidirectional threat → countermeasure → implementation → test-case matrix; 100 % of "reduce"-treated TARA threats and UN R155 CS.14–CS.16 requirements traced
- `SECURITY.md`: coordinated vulnerability disclosure policy aligned with OpenChain ISO/IEC 18974
- `scripts/autosar_scan.sh`: standalone local runner for the AUTOSAR forbidden-pattern scan (replaces the removed `compliance` CMake target)

### Added — Supply Chain & OSS Compliance (OpenChain ISO/IEC 5230 · 18974 · NIST CSF)

- `docs/COMPLIANCE.md` (ZZTA-CMP-001): requirement-by-requirement conformance mapping for OpenChain ISO/IEC 5230 (license compliance), ISO/IEC 18974 (security assurance), and NIST Cybersecurity Framework (Identify/Protect/Detect/Respond/Recover)
- `sbom/zzta-1.0.0.spdx.json`: SPDX 2.3 Software Bill of Materials — zzta_core has zero third-party dependencies; GoogleTest declared as `TEST_DEPENDENCY_OF` only
- `NOTICE`: third-party component inventory, license obligation analysis, and dedicated FOSS compliance contact (ISO/IEC 5230 §3.1.4)
- GoogleTest FetchContent pin changed from mutable tag `v1.14.0` to immutable commit hash `f8d7d77c` (ISO/IEC 18974 §3.3 / NIST CSF ID.SC supply-chain integrity)
- Pull request template extended with a Supply Chain / OSS Compliance checklist

### Added — Build System & CI

- CMake 3.20+ build system with `ZZTA_BUILD_TESTS`, `ZZTA_PRODUCTION_BUILD`, `ZZTA_ENABLE_ASAN`, `ZZTA_ENABLE_UBSAN` options
- `cmake/Toolchain-A53.cmake`: Cortex-A53/AArch64 with `-fno-exceptions -fno-rtti -Os`
- `cmake/Toolchain-M7.cmake`: Cortex-M7 bare-metal `arm-none-eabi` with `-fstack-usage`, nano.specs
- 7-job CI pipeline: build-and-test (GCC + Clang, ASan + UBSan), cross-compile (A53 + M7), stack-analysis, compliance-scan, doxygen-check, static-analysis (clang-tidy + cppcheck), coverage (gcovr gates: line >= 90 %, branch >= 85 %)
- AUTOSAR compliance scan: grep-based, fails CI on any `try/catch/throw`, `new/malloc`, `std::vector/map/string/shared_ptr/mutex`
- GoogleTest v1.14.0 via FetchContent: 81 test cases covering all nominal, error-injection, and integration paths

---

*(c) 2026 norxs Technology LLC. All rights reserved.*
