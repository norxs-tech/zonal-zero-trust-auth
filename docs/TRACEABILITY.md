# Requirements Traceability Matrix — norxs zonal-zero-trust-authenticator

**Document ID:** ZZTA-RTM-001
**Revision:** 1.0.0
**Date:** 2026-06-11
**Project:** zonal-zero-trust-authenticator v1.0.0
**Related:** ZZTA-TARA-001 (TARA) · ZZTA-HARA-001 (HARA) · ZZTA-VTR-001 (Test Report)
**Author:** norxs-lab
**(c) 2026 norxs Technology LLC. All rights reserved.**

---

## 1. Purpose

This matrix provides bidirectional traceability between identified threats
(ISO/SAE 21434 TARA), regulatory requirements (UN R155 §7.2.2), the
implementing code, and the verifying test cases — the evidence chain expected
by ISO/SAE 21434 §10/§11 work products and ASPICE SWE.6 / SUP.x traceability
practices. Every "reduce"-treated threat traces to at least one passing test.

## 2. Threat → Implementation → Verification

| Threat / Req. | Description | Countermeasure | Implementation (file · function) | Verifying Test Cases |
|---------------|-------------|----------------|----------------------------------|----------------------|
| **THREAT-03** | Authentication bypass via FSM state confusion | Strict 4-state FSM; illegal transitions rejected with explicit status | `SpdmProtocolEngine.cpp` · `ProcessAuthRequest()` / `ProcessAuthResponse()` state guards | `SpdmProtocolEngineTest.ProcessAuthRequest_InChallengeSent_ReturnsInvalidState` · `ProcessAuthRequest_WhenAuthenticated_ReturnsAlreadyAuthenticated` · `ProcessAuthResponse_FromUnauthenticated_InvalidState` · `FaultInjectionTest.ProcessAuthResponse_WithoutRequest_InvalidState` |
| **THREAT-04** | Replay of captured handshake frames | Fresh 256-bit random nonce per challenge; key bound to nonce | `CryptoPlatformInterface.cpp` · `GenerateRandomNonce()`; `SpdmProtocolEngine.cpp` challenge issuance | `SoftwareCryptoProviderTest.GenerateRandomNonce_TwoCallsDiffer` · `GenerateRandomNonce_NonceIsNonZero` · `SoftwareCryptoProviderTest.DeriveSessionKey_DifferentNoncesDifferentKeys` · `SpdmProtocolEngineTest.GetPendingChallenge_IsNonZero` |
| **THREAT-05** | Timing side-channel on comparisons | Constant-time volatile-accumulator comparison on all secret/ID compare paths | `CryptoPlatformInterface.cpp` · mock ECC verify; `SpdmProtocolEngine.cpp` · `FindPeerPublicKey()` | `SoftwareCryptoProviderTest.VerifyEccSignature_BitFlipReturnsFailed` · `VerifyEccSignature_WrongKeyReturnsFailed` *(functional correctness; constant-time property verified by code inspection — see note §4)* |
| **THREAT-07** | Peer / client-ID enumeration | Constant-time full-table peer lookup (no early exit) | `SpdmProtocolEngine.cpp` · `FindPeerPublicKey()` | `SpdmProtocolEngineTest.ProcessAuthRequest_UnknownPeer_ReturnsSignatureInvalid` · `NullPeerTable_RejectsAllPeers` · `SomeIpAdaptorTest.OnAuthRequest_UnknownPeer_ReturnsUnknownPeer` |
| **THREAT-08** | Key exhaustion / brute force | 3-strike anomaly counter → permanent lockout until power cycle | `TokenLifecycleManager.cpp` · `RevokeToken(is_anomaly)` / `RegisterToken()` lockout gate | `TokenLifecycleManagerTest.AnomalyLockout_AfterMaxAnomaly` · `AnomalyLockout_NonAnomalyDoesNotLockOut` |
| **THREAT-09** | Stale-session exploitation | 30 s token lifetime; lazy expiry on access + ≤ 15 s periodic scan | `TokenLifecycleManager.cpp` · `ValidateToken()` / `EvaluateTokenExpiry()` | `TokenLifecycleManagerTest.ValidateToken_Expired_LazyRevoke` · `EvaluateTokenExpiry_ExpiresStale` · `EvaluateTokenExpiry_DoesNotExpireYoung` · `EvaluateTokenExpiry_MultiToken_OnlyExpiresStale` · `SomeIpAdaptorTest.OnSessionTick_ExpiresSession` · `IntegrationTest.FullCycle_Handshake_Expire_Reauth` |

## 3. UN R155 §7.2.2 Derived Requirements

| Req. ID | Requirement | Implementation | Verifying Test Cases |
|---------|-------------|----------------|----------------------|
| **CS.14** | Continuous session monitoring | `EvaluateTokenExpiry()` — O(N) bounded periodic scan, ≤ 15 s tick | `TokenLifecycleManagerTest.EvaluateTokenExpiry_*` (3 cases) · `SomeIpAdaptorTest.OnSessionTick_ExpiresSession` |
| **CS.15** | Cryptographic agility | `CryptoPlatformInterface` pure-virtual PAL — provider swap without FSM change | `FaultInjectionTest.RngFault_ProcessAuthRequest_ReturnsCryptoError` · `Sha256Fault_ProcessAuthResponse_ReturnsCryptoError` (PAL substitution demonstrated via fault-injection provider) |
| **CS.16** | Key material erasure on revocation | `ZeroSlotSecrets()` volatile byte-write loop on every revocation/expiry path | `FaultInjectionTest.KeyZeroedAfterRevoke_NotReturnedByValidate` · `SpdmProtocolEngineTest.Revoke_TransitionsToRevoked` |

## 4. Verification Method Notes

- **Test** is the primary method; all rows above trace to the 81-case suite
  documented in [ZZTA-VTR-001](TEST_REPORT.md).
- **Constant-time properties (THREAT-05/07)** cannot be conclusively proven by
  functional unit tests. The reference evidence is structural code inspection
  (volatile accumulator, no data-dependent branch/early-exit). For production
  engagements norxs additionally performs dudect-style statistical timing
  measurement on target silicon — available as part of the commercial
  verification package.
- Robustness rows (malformed frames, null parameters) trace through
  `SomeIpAdaptorTest.OnAuthRequest_ShortFrame_InvalidFrame`,
  `OnAuthRequest_NullPayload_InvalidFrame`,
  `OnAuthResponse_ShortFrame_InvalidFrame`,
  `OnAuthResponse_NullPayload_InvalidFrame`,
  `TokenLifecycleManagerTest.RegisterToken_AllZeroClientId_ReturnsInvalidParam`,
  and `ValidateToken_NullKeyOut_DoesNotCrash`.

## 5. Coverage of the Matrix

| Population | Traced | Coverage |
|------------|-------:|---------:|
| TARA threats with treatment "reduce" | 5 / 5 | 100 % |
| UN R155 §7.2.2 derived requirements | 3 / 3 | 100 % |

---

*(c) 2026 norxs Technology LLC. All rights reserved.*
