/**
 * =====================================================================================
 * @file        ZztaVersion.hpp
 * @brief       Compile-time and runtime version identification for the
 *              zonal-zero-trust-authenticator software component. Provides
 *              AUTOSAR-style SW_MAJOR/SW_MINOR/SW_PATCH constants as well as
 *              a packed 32-bit version word and a human-readable version string,
 *              enabling integrating BSW layers to perform compatibility checks
 *              at startup per AUTOSAR SWS_BSWGeneral §7.3 (version checking).
 *              The component ID and vendor ID constants follow the AUTOSAR
 *              vendor/module numbering convention used by NXP S32 SDK BSW.
 * @project     zonal-zero-trust-authenticator
 * @standards   AUTOSAR C++14, ISO 26262 ASIL-D, AUTOSAR SWS_BSWGeneral
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * @note        This is a reference implementation showcasing norxs's SOA architecture.
 * =====================================================================================
 */

#ifndef ZZTA_VERSION_HPP
#define ZZTA_VERSION_HPP

#include <cstdint>

namespace zzta {

// ─────────────────────────────────────────────────────────────────────────────
// Vendor and module identification (AUTOSAR SWS_BSWGeneral §7.3.1)
// ─────────────────────────────────────────────────────────────────────────────

/** @brief AUTOSAR vendor ID for norxs Technology LLC (private range: 0xF000–0xFFFE). */
static constexpr uint16_t kVendorId{0xF001U};

/** @brief AUTOSAR module ID for the zonal-zero-trust-authenticator component. */
static constexpr uint16_t kModuleId{0x0101U};

// ─────────────────────────────────────────────────────────────────────────────
// Software version numbers (Semantic Versioning 2.0 — semver.org)
// INCREMENT RULES:
//   MAJOR — breaking API change (new method signatures, removed types)
//   MINOR — backward-compatible new features
//   PATCH — backward-compatible bug fixes only
// ─────────────────────────────────────────────────────────────────────────────

/** @brief Software major version. Breaking API change increments this. */
static constexpr uint8_t kSwMajorVersion{1U};

/** @brief Software minor version. New backward-compatible features increment this. */
static constexpr uint8_t kSwMinorVersion{0U};

/** @brief Software patch version. Bug fixes only; no API change. */
static constexpr uint8_t kSwPatchVersion{0U};

// ─────────────────────────────────────────────────────────────────────────────
// Packed version word — 0x00MMNNPP (Major.Minor.Patch in bytes 2-1-0)
// Enables single-register comparison in production diagnostics.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief 32-bit packed version: bits[23:16]=Major, bits[15:8]=Minor, bits[7:0]=Patch.
 *
 * Usage in DTC/UDS 0x22 data identifier or AUTOSAR Dcm_DidConfig:
 * @code
 *   uint8_t buf[3];
 *   buf[0] = static_cast<uint8_t>((zzta::kVersionWord >> 16U) & 0xFFU); // Major
 *   buf[1] = static_cast<uint8_t>((zzta::kVersionWord >>  8U) & 0xFFU); // Minor
 *   buf[2] = static_cast<uint8_t>( zzta::kVersionWord         & 0xFFU); // Patch
 * @endcode
 */
static constexpr uint32_t kVersionWord{
    (static_cast<uint32_t>(kSwMajorVersion) << 16U) |
    (static_cast<uint32_t>(kSwMinorVersion) <<  8U) |
     static_cast<uint32_t>(kSwPatchVersion)
};

// ─────────────────────────────────────────────────────────────────────────────
// Human-readable version string (NUL-terminated, .rodata)
// ─────────────────────────────────────────────────────────────────────────────

/** @brief NUL-terminated ASCII version string, e.g. "zzta/1.0.0". */
static constexpr char kVersionString[] = "zzta/1.0.0";

/** @brief Full component identification string including vendor. */
static constexpr char kComponentString[] =
    "norxs zonal-zero-trust-authenticator v1.0.0 "
    "(c) 2026 norxs Technology LLC";

// ─────────────────────────────────────────────────────────────────────────────
// AUTOSAR-style version check macro
// Used at include-time by integrating modules to enforce compatibility.
//
// Example usage in HseCryptoProvider.cpp:
//   #include "zzta/ZztaVersion.hpp"
//   ZZTA_CHECK_VERSION(1, 0, 0)   // Asserts that ZZTA is exactly v1.0.0
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Compile-time version compatibility assertion.
 *
 * Triggers a static_assert if the currently compiled ZZTA library version
 * does not match the expected (major, minor, patch) triple. This catches
 * header/library version skew at build time rather than at runtime.
 *
 * @param exp_major  Expected SW major version.
 * @param exp_minor  Expected SW minor version.
 * @param exp_patch  Expected SW patch version.
 */
#define ZZTA_CHECK_VERSION(exp_major, exp_minor, exp_patch)                          \
    static_assert(                                                                    \
        (::zzta::kSwMajorVersion == static_cast<uint8_t>(exp_major)) &&              \
        (::zzta::kSwMinorVersion == static_cast<uint8_t>(exp_minor)) &&              \
        (::zzta::kSwPatchVersion == static_cast<uint8_t>(exp_patch)),                \
        "ZZTA version mismatch: expected v" #exp_major "." #exp_minor "." #exp_patch \
        " but found a different version. Update the ZZTA library or this check.")

// ─────────────────────────────────────────────────────────────────────────────
// Static assertions — self-consistency checks
// ─────────────────────────────────────────────────────────────────────────────

static_assert(kVersionWord <= 0x00FFFFFFU,
    "Version word must fit in 24 bits (major.minor.patch each <= 0xFF).");

static_assert(sizeof(kVersionString) > 1U,
    "Version string must be non-empty.");

} // namespace zzta

#endif // ZZTA_VERSION_HPP
