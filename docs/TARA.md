# TARA — norxs zonal-zero-trust-authenticator

**Document ID:** ZZTA-TARA-001
**Revision:** 1.0.0
**Date:** 2026-06-03
**Project:** zonal-zero-trust-authenticator
**Standard:** ISO/SAE 21434:2021 §15 — Threat Analysis and Risk Assessment
**Related:** ZZTA-HARA-001 (ISO 26262-3 HARA)
**Author:** norxs-lab
**(c) 2026 norxs Technology LLC. All rights reserved.**

---

## 1. Scope and Item Definition

### 1.1 Item Under Analysis

The **zonal-zero-trust-authenticator** software component authenticates zone
node ECUs connecting to a Zonal Gateway via SOME/IP using SPDM DSP0274 v1.1
Challenge-Response. The item boundary covers:

- `SpdmProtocolEngine` — protocol FSM, nonce generation, signature verification
- `TokenLifecycleManager` — session table, expiry, anomaly lockout
- `CryptoPlatformInterface` PAL — cryptographic primitives abstraction

### 1.2 Assets

| Asset ID | Asset | Description | CIA Properties |
|----------|-------|-------------|---------------|
| **A-01** | SPDM Session Key | AES-256-GCM key protecting SOME/IP payload | C, I |
| **A-02** | Challenge Nonce | 256-bit random used to bind the handshake | I |
| **A-03** | ECC Private Key | Zone node signing key (stored on peer, not gateway) | C |
| **A-04** | Peer Public Key Table | `.rodata` table of known zone node public keys | I, A |
| **A-05** | Session Table | In-RAM list of active authenticated sessions | I, A |
| **A-06** | HKDF Master Salt | Platform secret used in key derivation | C |
| **A-07** | Authentication State | FSM state per zone node slot | I, A |
| **A-08** | SOME/IP Service Data | Application payload after successful auth | C, I |

---

## 2. Threat Scenarios

### THREAT-01 — Replay Attack on SPDM Response

| Field | Value |
|-------|-------|
| **Threat** | Attacker captures a valid `SpdmAuthResponse` and replays it on a subsequent connection attempt. |
| **Asset** | A-07 (Authentication State), A-08 (Service Data) |
| **Attack Vector** | Network (SOME/IP, 1000BASE-T1 automotive Ethernet) |
| **Attack Complexity** | Low — passive capture then retransmit |
| **Privileges Required** | None — physical access to bus |
| **CIA Impact** | I — authentication state falsely set to kAuthenticated |
| **CVSS v4.0 Base Score** | **8.7 (High)** |
| **Countermeasure** | CM-01: Per-handshake 256-bit TRNG nonce; nonce is embedded in signed digest |
| **Implementation** | `GenerateRandomNonce()` called fresh for each `ProcessAuthRequest()` |
| **Residual Risk** | Low — attacker must break 256-bit entropy to predict nonce |

---

### THREAT-02 — Signature Forgery (Authentication Bypass)

| Field | Value |
|-------|-------|
| **Threat** | Attacker crafts a forged `SpdmAuthResponse` without possessing the zone node's ECC private key. |
| **Asset** | A-07, A-01 |
| **Attack Vector** | Network |
| **Attack Complexity** | High — requires breaking ECDSA-P256 |
| **CIA Impact** | I, C — false authentication + session key compromise |
| **CVSS v4.0 Base Score** | **9.1 (Critical)** |
| **Countermeasure** | CM-02: ECDSA-P256 signature verification with SHA-256(nonce ∥ client_id) as message |
| **Implementation** | `VerifyEccSignature()` → HSE `HSE_SRV_ID_ECDSA_VERIFY` (production) |
| **Residual Risk** | Negligible — computationally infeasible under current NIST guidance |

---

### THREAT-03 — Authentication State Machine Bypass

| Field | Value |
|-------|-------|
| **Threat** | Software fault or protocol manipulation causes FSM to skip `kChallengeSent` and jump directly to `kAuthenticated` without verifying a signature. |
| **Asset** | A-07 |
| **Attack Vector** | Local (software fault injection, glitch attack on MCU) |
| **Attack Complexity** | Medium — requires physical access for hardware fault injection |
| **CIA Impact** | I — authentication bypass |
| **CVSS v4.0 Base Score** | **7.3 (High)** |
| **Countermeasure** | CM-03: FSM state guard checks at entry of every transition function; `kAuthenticated` reachable only via `ProcessAuthResponse()` after successful `VerifyEccSignature()` |
| **Implementation** | State guard: `if (state_ != State::kChallengeSent) return kInvalidState;` |
| **Residual Risk** | Low — multiple independent guards; hardware glitch requires precise timing |

---

### THREAT-04 — Session Key Leakage via Memory Disclosure

| Field | Value |
|-------|-------|
| **Threat** | Post-revocation session key material remains accessible in RAM via debug port, core dump, or cold-boot attack. |
| **Asset** | A-01 (Session Key), A-02 (Nonce), A-06 (Master Salt) |
| **Attack Vector** | Physical (JTAG, debug probe, cold-boot DRAM read) |
| **Attack Complexity** | Medium — requires physical access and specialised tooling |
| **CIA Impact** | C — retroactive decryption of captured SOME/IP traffic |
| **CVSS v4.0 Base Score** | **6.8 (Medium)** |
| **Countermeasure** | CM-04: `volatile` byte-write zeroing of all key and nonce fields on every revocation, expiry, and reset path |
| **Implementation** | `ZeroSlotSecrets()`, `SanitiseSecretMaterial()` — both use `volatile uint8_t*` loops |
| **Residual Risk** | Low — compiler cannot eliminate volatile writes; JTAG disabled in production via HSE fuse |

---

### THREAT-05 — Timing Side-Channel on Signature Verification

| Field | Value |
|-------|-------|
| **Threat** | Attacker measures response latency of `VerifyEccSignature()` or `FindSlotByClientId()` to infer partial information about the session key or registered client IDs. |
| **Asset** | A-01, A-04, A-05 |
| **Attack Vector** | Network (sub-millisecond timing measurement) |
| **Attack Complexity** | High — requires many oracle queries and statistical analysis |
| **CIA Impact** | C — partial key recovery enabling forgery |
| **CVSS v4.0 Base Score** | **5.9 (Medium)** |
| **Countermeasure** | CM-05: All secret comparisons use `volatile uint8_t` accumulator with no early-exit; entire buffer always scanned regardless of mismatch position |
| **Implementation** | Pattern used in: `ProcessAuthResponse()`, `FindPeerPublicKey()`, `FindSlotByClientId()`, `VerifyEccSignature()` |
| **Residual Risk** | Low — no branching on secret data; power-analysis not applicable to software path |

---

### THREAT-06 — Session Fixation / Static Key Reuse

| Field | Value |
|-------|-------|
| **Threat** | Compromised session key remains valid indefinitely, allowing sustained traffic decryption after a one-time compromise event. |
| **Asset** | A-01, A-08 |
| **Attack Vector** | Network (passive eavesdrop after key compromise) |
| **Attack Complexity** | Low — once key is known, all traffic is readable |
| **CIA Impact** | C — long-term traffic decryption |
| **CVSS v4.0 Base Score** | **7.5 (High)** |
| **Countermeasure** | CM-06: HKDF per-handshake session key (fresh nonce every time); `kTokenLifetimeMs = 30 000 ms` forced expiry |
| **Implementation** | `EvaluateTokenExpiry()` periodic scan; `kTokenLifetimeMs` in `TokenLifecycleManager.hpp` |
| **Residual Risk** | Low — maximum exposure window = 30 seconds |

---

### THREAT-07 — RNG Oracle / Nonce Prediction

| Field | Value |
|-------|-------|
| **Threat** | Attacker sends repeated invalid auth requests to observe nonces and statistically characterise the platform RNG, enabling future nonce prediction. |
| **Asset** | A-02 (Nonce) |
| **Attack Vector** | Network (high-frequency auth flood) |
| **Attack Complexity** | High — requires statistical analysis of 256-bit TRNG output |
| **CIA Impact** | I — nonce prediction breaks replay protection |
| **CVSS v4.0 Base Score** | **4.3 (Medium)** |
| **Countermeasure** | CM-07: Nonce generated **after** peer table lookup succeeds; unknown peers receive no nonce — oracle surface eliminated |
| **Implementation** | `ProcessAuthRequest()` step order: (1) version check, (2) peer table lookup, (3) `GenerateRandomNonce()` |
| **Residual Risk** | Low — TRNG output of 256 bits is computationally infeasible to characterise |

---

### THREAT-08 — Brute-Force Authentication Flood

| Field | Value |
|-------|-------|
| **Threat** | Attacker floods the gateway with invalid `SpdmAuthResponse` frames from one client ID, attempting to guess a valid ECC signature or exhaust the session table. |
| **Asset** | A-05 (Session Table), A-07 |
| **Attack Vector** | Network |
| **Attack Complexity** | Low — trivial to send many frames |
| **CIA Impact** | A — denial of service to legitimate zone nodes |
| **CVSS v4.0 Base Score** | **7.5 (High)** |
| **Countermeasure** | CM-08: `anomaly_count` incremented per failed `RevokeToken(is_anomaly=true)`; lockout after `kMaxAnomalyCount = 3` within one power cycle |
| **Implementation** | `TokenSlot::anomaly_count`, `TokenSlot::is_locked_out`, `TokenLifecycleManager::RevokeToken()` |
| **Residual Risk** | Medium — lockout is power-cycle-scoped; persistent DoS requires repeated power cycling |

---

### THREAT-09 — Session Table Exhaustion

| Field | Value |
|-------|-------|
| **Threat** | Attacker authenticates 8 fake zone nodes (using 8 stolen private keys) to fill the session table, preventing legitimate nodes from registering. |
| **Asset** | A-05, A-07 |
| **Attack Vector** | Network (requires 8 valid private keys) |
| **Attack Complexity** | High — requires physical compromise of zone node hardware |
| **CIA Impact** | A — denial of service |
| **CVSS v4.0 Base Score** | **6.5 (Medium)** |
| **Countermeasure** | CM-09: LRU eviction via `StaticCircularBuffer` ensures table never permanently full; oldest session always replaceable |
| **Implementation** | `RegisterToken()` → `insertion_order_.Pop()` → LRU eviction path |
| **Residual Risk** | Low — attacker must maintain 8 authenticated sessions simultaneously and continuously outpace LRU eviction |

---

### THREAT-10 — Cross-Peer Session Hijack

| Field | Value |
|-------|-------|
| **Threat** | Authenticated zone node A substitutes its session token for zone node B's, gaining access to B's services. |
| **Asset** | A-01, A-08 |
| **Attack Vector** | Local (requires network co-location) |
| **Attack Complexity** | Medium — requires a legitimate session on A |
| **CIA Impact** | C, I — unauthorized access to peer B's encrypted channel |
| **CVSS v4.0 Base Score** | **6.8 (Medium)** |
| **Countermeasure** | CM-10: `client_id` bound into HKDF IKM (`nonce ∥ client_id`) and into signed digest (`SHA-256(nonce ∥ client_id)`); each session key is uniquely tied to the authenticated client ID |
| **Implementation** | `ComputeChallengeDigest()`, `DeriveSessionKey()` both include `client_id` |
| **Residual Risk** | Negligible — key derivation is cryptographically bound to client identity |

---

## 3. Cybersecurity Goals

| CG ID | Description | CVSS Max | Threats |
|-------|-------------|----------|---------|
| **CG-01** | The ZZTA shall ensure that only zone nodes possessing a valid OEM-provisioned ECC private key can obtain an authenticated session. | 9.1 | T-02, T-03 |
| **CG-02** | The ZZTA shall ensure that session keys are unique per handshake and expire within 30 seconds. | 7.5 | T-01, T-06 |
| **CG-03** | The ZZTA shall erase all session key material from RAM within the revocation call frame. | 6.8 | T-04 |
| **CG-04** | The ZZTA shall prevent brute-force attacks by locking out clients after 3 consecutive anomaly events. | 7.5 | T-08 |
| **CG-05** | All secret-bearing comparisons shall execute in constant time with no data-dependent branching. | 5.9 | T-05 |

---

## 4. Cybersecurity Requirements (Technical)

| CR ID | Requirement | CG | Implementation Reference |
|-------|-------------|-----|--------------------------|
| **CR-01** | The SPDM challenge nonce shall be 256-bit cryptographically random and generated fresh per handshake. | CG-01, CG-02 | `GenerateRandomNonce()` |
| **CR-02** | The signed digest shall be `SHA-256(nonce ∥ client_id)` binding both freshness and identity. | CG-01 | `ComputeChallengeDigest()` |
| **CR-03** | Signature verification shall use ECDSA-P256 with a key from the `.rodata` peer table. | CG-01 | `VerifyEccSignature()` |
| **CR-04** | Session tokens shall expire within `kTokenLifetimeMs` (30 000 ms) monitored by periodic scan. | CG-02 | `EvaluateTokenExpiry()` |
| **CR-05** | Session key derivation shall use HKDF-SHA-256 with IKM = `nonce ∥ client_id`. | CG-02 | `DeriveSessionKey()` |
| **CR-06** | Session key and nonce fields shall be overwritten with zero bytes using `volatile` writes on revocation. | CG-03 | `ZeroSlotSecrets()`, `SanitiseSecretMaterial()` |
| **CR-07** | Clients shall be locked out after `kMaxAnomalyCount` (3) anomalous events within one power cycle. | CG-04 | `RevokeToken(is_anomaly=true)` |
| **CR-08** | All comparisons involving session keys, client IDs, or signatures shall use `volatile` accumulators with full-length iteration. | CG-05 | Constant-time pattern throughout |
| **CR-09** | SPDM nonce generation shall occur only after successful peer table lookup. | CG-01 | `ProcessAuthRequest()` step ordering |
| **CR-10** | The HKDF master salt shall be stored in HSE key slot 0 (OTP-protected) in production builds. | CG-02, CG-03 | `HseCryptoProvider` (production) |

---

## 5. Attack Feasibility Ratings

Using ISO/SAE 21434 Annex B attack feasibility approach:

| Threat | Elapsed Time | Expertise | Knowledge | Window | Equipment | **Feasibility** |
|--------|-------------|-----------|-----------|--------|-----------|----------------|
| T-01 Replay | < 1 day | Proficient | Public | Unlimited | Standard | **Medium** |
| T-02 Forge | > 1 year | Expert | Restricted | Unlimited | Specialised | **Very Low** |
| T-03 FSM bypass | < 1 week | Expert | Sensitive | < 1 day | Bespoke | **Low** |
| T-04 Memory dump | < 1 day | Proficient | Public | Physical | Standard | **Medium** |
| T-05 Timing SC | > 1 month | Expert | Restricted | Unlimited | Specialised | **Low** |
| T-06 Stale key | < 1 day | Layman | Public | Unlimited | Standard | **High** |
| T-07 RNG oracle | > 1 year | Expert | Restricted | Unlimited | Specialised | **Very Low** |
| T-08 Brute-force | < 1 day | Layman | Public | Unlimited | Standard | **High** |
| T-09 Table exhaust | < 1 week | Proficient | Public | Unlimited | Standard | **Medium** |
| T-10 Hijack | < 1 month | Expert | Sensitive | Unlimited | Specialised | **Low** |

---

## 6. Residual Risk Summary

All threats have been reduced to **Low** or **Negligible** residual risk after countermeasure
application, with the exception of:

- **T-08** (Brute-force): Residual **Medium** — lockout scope is power-cycle only. Production
  deployments should supplement with SOME/IP rate limiting at the transport layer and
  persistent anomaly logging to HSE secure storage.

- **T-06** (Session Fixation): Residual risk is fully mitigated by the 30-second expiry
  and per-handshake key derivation. The `kTokenLifetimeMs` constant may be tuned by the
  integrating OEM to match their specific TARA-defined exposure window.

---

## 7. Verification Evidence

| Countermeasure | Test Case | CI Job |
|----------------|-----------|--------|
| CM-01 (Nonce freshness) | `GenerateRandomNonce_TwoCallsProduceDifferentNonces` | `build-and-test` |
| CM-02 (ECDSA verify) | `VerifyEccSignature_ValidSignatureReturnsOk`, `WrongKeyReturnsVerifyFailed` | `build-and-test` |
| CM-03 (FSM guard) | `ProcessAuthRequest_InChallengeSent_ReturnsInvalidState` | `build-and-test` |
| CM-04 (Key erasure) | `FaultInjection_KeyZeroedAfterRevoke` | `build-and-test` |
| CM-05 (Constant-time) | `FaultInjection_ConstantTimeCompare_NoEarlyExit` | `build-and-test` |
| CM-06 (Expiry) | `EvaluateTokenExpiry_ExpiresOldTokens` | `build-and-test` |
| CM-07 (Nonce oracle) | `ProcessAuthRequest_UnknownPeer_ReturnsSignatureInvalid` | `build-and-test` |
| CM-08 (Lockout) | `AnomalyLockout_AfterMaxAnomaly_ClientIsLockedOut` | `build-and-test` |
| CM-09 (LRU) | `TableFull_LRUEviction_OldestSlotEvicted` | `build-and-test` |
| CM-10 (Bound key) | `FullHandshake_DifferentClientIds_ProduceDifferentKeys` | `build-and-test` |

---

*norxs Technology LLC — Safety Engineering, Built from the Ground Up.*
*(c) 2026 norxs Technology LLC. All rights reserved. | https://norxs.com*
