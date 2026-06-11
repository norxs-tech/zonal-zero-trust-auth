# Compliance Statement — OpenChain ISO/IEC 5230 · ISO/IEC 18974 · NIST CSF

**Document ID:** ZZTA-CMP-001
**Revision:** 1.0.0
**Date:** 2026-06-11
**Project:** zonal-zero-trust-authenticator v1.0.0
**Related:** ZZTA-VTR-001 (Test Report) · ZZTA-RTM-001 (Traceability) · ZZTA-TARA-001 (TARA)
**Author:** norxs-lab
**(c) 2026 norxs Technology LLC. All rights reserved.**

---

## 1. Purpose

norxs Technology LLC operates an open source program conformant with
**OpenChain ISO/IEC 5230:2020** (open source license compliance) and
**OpenChain ISO/IEC 18974:2023** (open source security assurance), aligned
with the **NIST Cybersecurity Framework**. This document maps each
specification's key requirements to the concrete, verifiable artifacts in
this repository — so a procurement or compliance reviewer can audit the
evidence without contacting norxs.

## 2. OpenChain ISO/IEC 5230 — License Compliance Mapping

| §5230 Requirement | Repository Evidence |
|-------------------|---------------------|
| §3.1.1 Documented policy | norxs Open Source Policy (program level); per-repo summary in [`NOTICE`](../NOTICE) |
| §3.1.4 Standard process to respond to external FOSS inquiries | Dedicated contact: contact@norxs.com, subject `[OSS-COMPLIANCE]` — published in [`NOTICE`](../NOTICE) and on https://www.norxs.com/ |
| §3.2.1 Bill of materials for each supplied software release | SPDX 2.3 SBOM: [`sbom/zzta-1.0.0.spdx.json`](../sbom/zzta-1.0.0.spdx.json), regenerated per release |
| §3.3.1 Compliance artifacts accompany the supplied software | [`LICENSE`](../LICENSE) (norxs RI v1.0), [`NOTICE`](../NOTICE) (component inventory + copyright notices), SBOM — all in-repo |
| §3.4.1 Awareness of obligations from identified licenses | One third-party component (GoogleTest, BSD-3-Clause): build-time test dependency only, not redistributed, never linked into `zzta_core` — obligation analysis recorded in [`NOTICE`](../NOTICE) and the SBOM `TEST_DEPENDENCY_OF` relationship |

**License identification convention:** all repository content is
`LicenseRef-norxs-RI-1.0` (declared in the SBOM's
`hasExtractedLicensingInfos`); the production library has **zero** third-party
code, which keeps the obligation surface empty by construction.

## 3. OpenChain ISO/IEC 18974 — Security Assurance Mapping

| §18974 Requirement | Repository Evidence |
|--------------------|---------------------|
| §3.1.1 Documented security assurance policy & procedure | This document + [`SECURITY.md`](../SECURITY.md) |
| §3.1.4 Standard process for handling externally reported vulnerabilities | [`SECURITY.md`](../SECURITY.md): private reporting channel, acknowledgement ≤ 3 business days, CVSS v3.1 triage ≤ 7 days, remediation ≤ 90 days, coordinated disclosure |
| §3.2.1 Identify structural/component information of supplied software | SPDX SBOM with commit-hash-pinned dependency coordinates |
| §3.3.1 Method to detect known vulnerabilities in components | Single test-only dependency (GoogleTest) pinned by **commit hash** in `CMakeLists.txt`; SBOM carries a CPE locator for `zzta_core` enabling downstream NVD matching; dependency review on every version bump (PR template checklist) |
| §3.3.2 Known vulnerabilities addressed before supply | Release gate: CI must be fully green (7 jobs) including cppcheck `--error-exitcode=1`, ASan/UBSan test run, and AUTOSAR pattern scan — see [`TEST_REPORT.md`](TEST_REPORT.md) |

**Secure development evidence beyond §18974 minimum:** threat analysis
([`TARA.md`](TARA.md)), threat-to-test traceability
([`TRACEABILITY.md`](TRACEABILITY.md)), constant-time comparison design,
key-zeroization-on-revocation with dedicated fault-injection tests.

## 4. NIST Cybersecurity Framework Alignment

| CSF Function | Category | Repository Practice |
|--------------|----------|---------------------|
| **IDENTIFY** | ID.AM (Asset Management) | SPDX SBOM enumerates all software assets and dependency relationships |
| | ID.RA (Risk Assessment) | ISO/SAE 21434 TARA ([`TARA.md`](TARA.md)) and ISO 26262-3 HARA ([`HARA_zonal_zero_trust.md`](HARA_zonal_zero_trust.md)) |
| | ID.SC (Supply Chain) | Commit-hash-pinned dependency; no vendored third-party code; SBOM with download coordinates |
| **PROTECT** | PR.AC (Access Control) | The product itself implements Zero-Trust continuous authentication (SPDM challenge-response, 30 s session expiry, anomaly lockout) |
| | PR.DS (Data Security) | Key material zeroization on every revocation path (`ZeroSlotSecrets()`, volatile write loop — UN R155 CS.16); zero-heap design eliminates use-after-free classes |
| | PR.IP (Protective Processes) | 7-job gated CI: sanitizers, static analysis, coverage thresholds, AUTOSAR pattern scan, stack budget |
| **DETECT** | DE.CM (Continuous Monitoring) | Product: ≤ 15 s periodic session monitoring (`EvaluateTokenExpiry()` — UN R155 CS.14). Process: CI runs on every push/PR |
| | DE.DP (Detection Processes) | 3-strike anomaly counter with permanent lockout (THREAT-08 countermeasure) |
| **RESPOND** | RS.RP / RS.CO (Response & Communications) | Vulnerability response process and timelines in [`SECURITY.md`](../SECURITY.md); coordinated disclosure with reporter credit |
| | RS.MI (Mitigation) | Product: revocation callback forces immediate SOME/IP channel teardown and re-authentication |
| **RECOVER** | RC.RP (Recovery Planning) | Product: deterministic `Reset()` → re-authentication path, verified by `IntegrationTest.FullCycle_Handshake_Expire_Reauth`; Process: fixes delivered as patch releases per SemVer with CHANGELOG disclosure |

## 5. Scope and Limitations

- ISO/IEC 5230 and 18974 are **program-level** specifications: conformance is
  a property of the norxs open source program. This document demonstrates how
  this specific repository implements the program's required processes.
- NIST CSF alignment is a self-assessment mapping, not a third-party
  certification.
- The dependency-vulnerability monitoring obligation (§18974 §3.3.1) is
  lightweight here by design: the production library has zero third-party
  dependencies, and the single test dependency is hash-pinned and reviewed on
  every bump.

---

*(c) 2026 norxs Technology LLC. All rights reserved.*
