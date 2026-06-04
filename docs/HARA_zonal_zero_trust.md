# HARA — norxs zonal-zero-trust-authenticator

**Document ID:** ZZTA-HARA-001
**Revision:** 1.0.0
**Date:** 2026-06-03
**Project:** zonal-zero-trust-authenticator
**Standard:** ISO 26262-3:2018 §6 — Hazard Analysis and Risk Assessment
**Author:** norxs-lab
**(c) 2026 norxs Technology LLC. All rights reserved.**

> **Scope:** This HARA covers the software boundary of the
> zonal-zero-trust-authenticator as deployed on an NXP S32G Zonal Gateway ECU.
> It identifies functional hazards arising from authentication failures, session
> management faults, and cryptographic service failures, and assigns ASIL
> ratings using the Severity × Exposure × Controllability matrix defined in
> ISO 26262-3 §6.4.

---

## 1. Item Definition

### 1.1 Item

The **zonal-zero-trust-authenticator** is a software item that authenticates
zone node ECUs connecting to a Zonal Gateway over SOME/IP using the SPDM
DSP0274 v1.1 Challenge-Response protocol. It replaces static SecOC symmetric
keys with per-session HKDF-derived AES-256-GCM session keys. The item manages
up to eight concurrent authenticated sessions and enforces session expiry,
anomaly lockout, and session key erasure.

### 1.2 Item Boundary

| In Scope | Out of Scope |
|----------|-------------|
| `SpdmProtocolEngine` FSM | SOME/IP transport stack |
| `TokenLifecycleManager` | AES-256-GCM payload encryption |
| `CryptoPlatformInterface` PAL | OEM PKI certificate chain |
| Session key derivation (HKDF) | NXP HSE firmware internals |
| Session expiry monitoring | Zone node firmware |

### 1.3 Operating Modes

| Mode | Description |
|------|-------------|
| **Normal** | All zone nodes authenticated; session keys active |
| **Re-Auth** | One or more sessions expired; zone node retrying handshake |
| **Degraded** | One or more sessions revoked due to anomaly; affected zone degraded |
| **Emergency** | All sessions revoked; gateway forwards only life-critical traffic |

---

## 2. Hazard Identification

### H-01: Unauthenticated Zone Node Gains Full Network Access

| Field | Value |
|-------|-------|
| **Hazard** | A zone node that has not completed SPDM authentication is granted access to encrypted SOME/IP services. |
| **Cause** | Authentication bypass via invalid state transition (THREAT-03). |
| **Effect** | Attacker can inject forged sensor data (e.g. phantom obstacle) into ADAS domain. |
| **Failure Mode** | FSM state guard bypassed; session token granted without verified signature. |
| **ASIL Analysis** | — |
| Severity (S) | **S3** — potential crash with risk of life-threatening injuries |
| Exposure (E) | **E4** — vehicle powered on during normal operation (high frequency) |
| Controllability (C) | **C3** — difficult or impossible for driver to control |
| **ASIL** | **ASIL D** |

### H-02: Expired Session Key Continues to Encrypt Traffic

| Field | Value |
|-------|-------|
| **Hazard** | A session that has exceeded `kTokenLifetimeMs` is not revoked; its key remains active. |
| **Cause** | `EvaluateTokenExpiry()` not called within the required 15-second window. |
| **Effect** | Extended window for session hijack; stale key compromises AES-256-GCM integrity. |
| **Failure Mode** | OS timer misconfiguration; timer ISR missed; overflow in `current_time_ms`. |
| **ASIL Analysis** | — |
| Severity (S) | **S2** — moderate injury risk via incorrect ADAS command |
| Exposure (E) | **E3** — exposure during highway driving |
| Controllability (C) | **C2** — driver may be able to counteract |
| **ASIL** | **ASIL B** |

### H-03: Session Key Material Leaked via Memory Dump

| Field | Value |
|-------|-------|
| **Hazard** | AES-256-GCM session key remains in RAM after session revocation. |
| **Cause** | Compiler eliminates `volatile` memset if coded incorrectly. |
| **Effect** | Cold-boot attack recovers active session keys; SOME/IP traffic decryptable. |
| **Failure Mode** | Dead-store elimination removes zeroing loop. |
| **ASIL Analysis** | — |
| Severity (S) | **S2** — data exfiltration enabling targeted injection |
| Exposure (E) | **E2** — physical access required, limited to workshop/theft scenarios |
| Controllability (C) | **C1** — driver cannot detect |
| **ASIL** | **ASIL A** |

### H-04: Brute-Force SPDM Authentication Flood

| Field | Value |
|-------|-------|
| **Hazard** | Attacker floods the SPDM endpoint with invalid AUTH responses to saturate the session table or exhaust RNG entropy. |
| **Cause** | No rate limiting or anomaly counter enforced. |
| **Effect** | Legitimate zone nodes cannot authenticate; safety-relevant services denied. |
| **Failure Mode** | All session slots occupied by in-progress or locked handshakes. |
| **ASIL Analysis** | — |
| Severity (S) | **S2** — loss of ADAS or chassis control service |
| Exposure (E) | **E4** — vehicle network accessible via OBD-II or Ethernet port |
| Controllability (C) | **C2** — driver may detect degraded performance |
| **ASIL** | **ASIL B** |

### H-05: Incorrect Session Key Derived (KDF Input Fault)

| Field | Value |
|-------|-------|
| **Hazard** | `DeriveSessionKey()` produces a key different from what the zone node expects, causing all subsequent authenticated frames to fail MAC verification. |
| **Cause** | Bit fault in nonce or client_id buffer during HKDF computation. |
| **Effect** | All zone node communication fails; zone domain goes silent. |
| **Failure Mode** | Transient fault in SRAM or RNG output buffer. |
| **ASIL Analysis** | — |
| Severity (S) | **S1** — minor injury risk; loss of comfort functions |
| Exposure (E) | **E3** — exposure under normal driving |
| Controllability (C) | **C2** — driver can compensate |
| **ASIL** | **QM** |

---

## 3. Safety Goals

| Safety Goal ID | Description | ASIL | Source Hazard |
|---------------|-------------|------|---------------|
| **SG-01** | The zonal-zero-trust-authenticator shall never grant authenticated session status to any zone node that has not successfully completed the SPDM Challenge-Response handshake with a valid ECDSA-P256 signature. | **ASIL D** | H-01 |
| **SG-02** | The zonal-zero-trust-authenticator shall revoke all session tokens whose age exceeds `kTokenLifetimeMs` (30 seconds) within one tick period (≤ 15 seconds) of the expiry point. | **ASIL B** | H-02 |
| **SG-03** | The zonal-zero-trust-authenticator shall overwrite all session key and nonce material with zero bytes within the same call frame that revokes or expires the session. | **ASIL A** | H-03 |
| **SG-04** | The zonal-zero-trust-authenticator shall limit successful authentication attempts from any single client ID to prevent session table exhaustion; after `kMaxAnomalyCount` (3) consecutive anomaly events the client shall be locked out for the duration of the ECU power cycle. | **ASIL B** | H-04 |

---

## 4. Functional Safety Requirements (High-Level)

### FSR-SG01-01 — Authentication State Machine

**Derived from:** SG-01 / ASIL D

The `SpdmProtocolEngine` shall implement a deterministic, zero-allocation FSM
with exactly four states (`kUnauthenticated`, `kChallengeSent`, `kAuthenticated`,
`kRevoked`). The state `kAuthenticated` shall be entered **only** via the
`ProcessAuthResponse()` method when `CryptoPlatformInterface::VerifyEccSignature()`
returns `CryptoStatus::kOk`.

**Verification:** Unit test `SpdmProtocolEngineTest.FullNominalHandshake` and
negative tests `InvalidSignature`, `WrongVersion`, `ClientIdMismatch`.

### FSR-SG01-02 — Nonce-Bound Signed Digest

**Derived from:** SG-01 / ASIL D

The challenge digest signed by the zone node shall be `SHA-256(nonce ∥ client_id)`
where `nonce` is a fresh random value generated via
`CryptoPlatformInterface::GenerateRandomNonce()` for each handshake instance.
The nonce shall never be reused across handshake attempts.

**Verification:** Unit test `SpdmProtocolEngineTest.NonceBoundToHandshake`.

### FSR-SG02-01 — Periodic Expiry Monitoring

**Derived from:** SG-02 / ASIL B

The integrating application shall invoke
`TokenLifecycleManager::EvaluateTokenExpiry(current_time_ms)` at a rate no
lower than once per `kTokenLifetimeMs / 2` milliseconds (= 15 000 ms).
The `EvaluateTokenExpiry()` function shall revoke all slots whose age exceeds
`kTokenLifetimeMs` in a single bounded-time scan of `O(kMaxActiveSessions)`.

**Verification:** Unit test `TokenLifecycleManagerTest.PeriodicExpiry`.

### FSR-SG03-01 — Volatile Key Erasure

**Derived from:** SG-03 / ASIL A

Session key and nonce fields within a `TokenSlot` shall be overwritten with
zero bytes using a `volatile uint8_t*` write loop that cannot be eliminated
by any conformant C++14 compiler optimisation pass (`-O0` through `-O3`).
This erasure shall occur atomically within `ZeroSlotSecrets()` before
`is_active` is set to `false`.

**Verification:** CI `-fstack-usage` and dead-store sanitiser; unit test
`TokenLifecycleManagerTest.RevokeZeroesKey`.

### FSR-SG04-01 — Anomaly Lockout

**Derived from:** SG-04 / ASIL B

For each `TokenSlot`, the `anomaly_count` field shall be incremented on every
call to `RevokeToken(client_id, is_anomaly=true)`. When `anomaly_count >=
kMaxAnomalyCount`, the `is_locked_out` flag shall be set to `true` and shall
not be clearable within the same ECU power cycle (no API to reset `is_locked_out`).

**Verification:** Unit test `TokenLifecycleManagerTest.AnomalyLockout`.

---

## 5. ASIL Decomposition

Where the same safety goal must be achieved by a software element with no
redundant hardware path, the full ASIL rating is allocated to the single
software component (no decomposition).

| Safety Goal | ASIL | Software Element | Decomposition |
|-------------|------|------------------|--------------|
| SG-01 | ASIL D | `SpdmProtocolEngine` | None — single responsibility |
| SG-02 | ASIL B | `TokenLifecycleManager::EvaluateTokenExpiry()` | None |
| SG-03 | ASIL A | `TokenLifecycleManager::ZeroSlotSecrets()` | None |
| SG-04 | ASIL B | `TokenLifecycleManager::RevokeToken()` | None |

---

## 6. Freedom from Interference

The three software modules (`CryptoPlatformInterface`, `SpdmProtocolEngine`,
`TokenLifecycleManager`) share no global mutable state. All coupling is through
explicit function arguments and return codes. There are no shared static
variables between modules.

**Memory partitioning:**

- `SpdmProtocolEngine` accesses only its own member variables and the injected PAL reference.
- `TokenLifecycleManager` accesses only its own `session_table_` and `insertion_order_`.
- The PAL (`SoftwareCryptoProvider` / `HseCryptoProvider`) holds only its LFSR state or HSE handle.

This satisfies ISO 26262-6 §7.4.14 (freedom from interference between software
elements of different ASIL ratings) at the design level. Runtime isolation
(MMU page boundaries on A53, MPU regions on M7) is the responsibility of the
integrating BSP/RTOS configuration.

---

*norxs Technology LLC — Safety Engineering, Built from the Ground Up.*
*(c) 2026 norxs Technology LLC. All rights reserved. | https://norxs.com*
