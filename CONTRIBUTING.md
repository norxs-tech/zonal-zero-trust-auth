# Contributing to norxs zonal-zero-trust-authenticator

**norxs Technology LLC** | Safety Engineering, Built from the Ground Up.

Thank you for your interest in contributing. This is a safety-critical and
cybersecurity-critical reference implementation. All contributions must meet
the coding, documentation, and review standards described below before they
can be accepted.

---

## Coding Standard

This project implements **AUTOSAR C++14**. Every contribution to `src/` and
`include/` **must** comply with all of the following constraints — checked
automatically by CI job `compliance-scan`:

| Constraint | Requirement |
|-----------|-------------|
| `try` / `catch` / `throw` | **0** occurrences |
| `new` / `delete` / `malloc` / `free` | **0** occurrences |
| `std::vector` / `std::map` / `std::string` | **0** occurrences |
| `std::shared_ptr` / `std::unique_ptr` | **0** occurrences |
| `std::mutex` / `lock_guard` | **0** occurrences |
| Dynamic containers | **Forbidden** — use `std::array` with compile-time N |
| Fixed-size buffers | **Required** — `constexpr std::size_t` for all sizes |
| Error propagation | **Return codes only** — `CryptoStatus`, `SpdmStatus`, `TlmStatus` |
| `[[nodiscard]]` | **Required** on all functions returning a status code |
| RTTI (`dynamic_cast`, `typeid`) | **Forbidden** — compile with `-fno-rtti` |

---

## Doxygen Header

Every new or modified `.hpp` / `.cpp` file **must** carry the complete
norxs Doxygen header (verified by CI job `doxygen-check`):

```cpp
/**
 * =====================================================================================
 * @file        [filename.hpp or filename.cpp]
 * @brief       [One comprehensive paragraph, minimum 2 sentences.]
 * @project     zonal-zero-trust-authenticator
 * @standards   AUTOSAR C++14, ISO/SAE 21434, UN R155, ISO 26262 ASIL-D
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * @note        This is a reference implementation showcasing norxs's SOA architecture.
 * =====================================================================================
 */
```

---

## Security & Safety Requirements

Before opening a pull request, confirm that:

1. **No new timing side-channels** are introduced in any comparison path
   involving cryptographic material. All comparisons over secret buffers must
   use a `volatile uint8_t accumulator` pattern identical to the existing code.

2. **Secret material is zeroed** via a volatile byte-write loop on every exit
   path from a function that holds a session key, nonce, or derived key in a
   local variable.

3. **State transitions are guarded** — every FSM function begins with a state
   check and returns an appropriate status code if the current state is illegal.

4. **WCET is bounded** — no new unbounded loops may be added to any function
   called from `EvaluateTokenExpiry()` or any ISR context.

5. **ISO/SAE 21434 impact assessed** — if your change introduces a new data
   flow or interface, note whether it intersects any threat in the project TARA
   and describe the countermeasure.

---

## Commit Message Convention

```
<type>: <short summary> (max 72 chars)

- [module or file]: [what changed and why]
```

Types: `feat` · `fix` · `docs` · `refactor` · `test` · `chore` · `style` · `perf`

---

## Pull Request Process

1. Fork the repository and create a feature branch from `develop`.
2. Run the full test suite locally: `ctest --output-on-failure`.
3. Run the compliance scan: `cmake --build build --target compliance`.
4. Fill in every section of the PR template.
5. At least one norxs-lab reviewer must approve before merge to `main`.

---

## Contact

For questions about the safety or cybersecurity architecture, contact
**norxs Technology LLC** directly via https://norxs.com.

Do **not** use GitHub Issues to report security vulnerabilities.

---

*(c) 2026 norxs Technology LLC. All rights reserved.*
