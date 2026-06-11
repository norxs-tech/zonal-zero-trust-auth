## Summary

<!-- One paragraph: what does this PR do and why? -->

## Motivation

Closes #

## Module(s) Changed

- [ ] CryptoPlatformInterface / SoftwareCryptoProvider
- [ ] SpdmProtocolEngine
- [ ] TokenLifecycleManager
- [ ] StaticCircularBuffer
- [ ] SomeIpAdaptor
- [ ] ZztaVersion
- [ ] CMake / Build System
- [ ] CI / GitHub Actions
- [ ] Documentation only

## AUTOSAR C++14 Compliance Checklist

- [ ] `try` / `catch` / `throw` — **0** occurrences in production files
- [ ] `new` / `delete` / `malloc` / `free` — **0** occurrences in production files
- [ ] `std::vector` / `std::map` / `std::string` / `std::shared_ptr` — **0** occurrences
- [ ] `std::mutex` / `lock_guard` — **0** occurrences
- [ ] All new functions return `[[nodiscard]]` status codes where applicable
- [ ] Doxygen header present on every new/modified file
- [ ] `static_assert` used to verify all compile-time size invariants

## Safety / Security Checklist

- [ ] No new timing side-channels introduced in ECC / HMAC comparison paths
- [ ] Secret material (session keys, nonces) zeroed via volatile loops on all exit paths
- [ ] All FSM state transitions explicitly guarded (no implicit fall-through)
- [ ] `EvaluateTokenExpiry()` WCET remains O(kMaxActiveSessions) bounded
- [ ] Anomaly counter incremented on all rejection paths in SpdmProtocolEngine
- [ ] ISO/SAE 21434 TARA impact assessed for any new interface or data path

## Supply Chain / OSS Compliance Checklist (ISO/IEC 5230 · 18974)

- [ ] No new third-party code vendored into the repository
- [ ] Any dependency version bump is pinned by **commit hash** (not tag) and reviewed for known vulnerabilities
- [ ] `sbom/zzta-*.spdx.json` and `NOTICE` updated if any dependency or license changed
- [ ] `docs/TRACEABILITY.md` updated if threats, requirements, or test mappings changed

## Testing

```
# Host build with ASan + UBSan
cmake -B build -DZZTA_BUILD_TESTS=ON -DZZTA_ENABLE_ASAN=ON -DZZTA_ENABLE_UBSAN=ON
cmake --build build --target zzta_tests
ctest --test-dir build --output-on-failure

# Compliance scan
./scripts/autosar_scan.sh
```

Paste `ctest` output here:
```

```

## Notes for Reviewer

<!-- Anything the reviewer should pay special attention to. -->
