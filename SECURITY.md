# Security Policy

**norxs Technology LLC** | Safety Engineering, Built from the Ground Up.

norxs operates a security assurance program conformant with
**OpenChain Security Assurance Specification (ISO/IEC 18974)** and aligned with
the **NIST Cybersecurity Framework**. This policy covers the
zonal-zero-trust-authenticator reference implementation.

The full requirement-by-requirement conformance mapping (ISO/IEC 5230,
ISO/IEC 18974, NIST CSF) is maintained in
[`docs/COMPLIANCE.md`](docs/COMPLIANCE.md). The SPDX SBOM for this release is
at [`sbom/zzta-1.0.0.spdx.json`](sbom/zzta-1.0.0.spdx.json).

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Active |

---

## Reporting a Vulnerability

If you discover a security vulnerability in this repository, please report it
**privately** — do not open a public GitHub issue.

- **Email:** contact@norxs.com (subject line: `[SECURITY] zonal-zero-trust-authenticator`)
- **Web:** https://www.norxs.com/ — contact form (select security topic)

Please include:

1. Affected file(s) and commit hash or release version
2. A description of the vulnerability and its potential impact
3. Steps to reproduce (proof-of-concept code is welcome)
4. Any suggested remediation, if available

### What to expect

| Stage | Target |
|-------|--------|
| Acknowledgement of report | within 3 business days |
| Initial triage and severity assessment (CVSS v3.1) | within 7 business days |
| Remediation plan or fix for confirmed issues | within 90 days, severity-dependent |
| Coordinated disclosure | after fix is released, credit given unless anonymity requested |

---

## Scope Notes for This Reference Implementation

This repository is a **reference implementation**. Two properties are
intentional design decisions, documented in
[`docs/architecture.md`](docs/architecture.md) §14, and are **not**
vulnerabilities:

- **`SoftwareCryptoProvider` is a deterministic mock** (LFSR-32 PRNG, mock ECC
  verification). It exists for CI and host-based unit testing only. A
  compile-time `static_assert` guard blocks it from linking into builds
  configured with `ZZTA_PRODUCTION_BUILD=ON`. Production deployments must use
  a hardware-backed provider (e.g. NXP HSE, Arm TrustZone-M).
- **The peer public-key table is compile-time static.** Production key
  provisioning, storage, and rotation are integration-specific and delivered
  under commercial engagement.

Reports demonstrating that these guards can be **bypassed** (e.g. the mock
provider linking into a production-flagged build) are in scope and very much
welcome.

---

## Security Verification Applied to This Repository

- AddressSanitizer + UndefinedBehaviorSanitizer on the full 81-case test suite (CI Job 1)
- cppcheck (CERT/MISRA subset) with `--error-exitcode=1` (CI Job 6)
- AUTOSAR C++14 forbidden-pattern gate: zero heap, zero exceptions (CI Job 4)
- Threat analysis: [`docs/TARA.md`](docs/TARA.md) (ISO/SAE 21434 §15)
- Threat-to-test traceability: [`docs/TRACEABILITY.md`](docs/TRACEABILITY.md)

---

*(c) 2026 norxs Technology LLC. All rights reserved.*
