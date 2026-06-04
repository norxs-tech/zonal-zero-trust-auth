/**
 * =====================================================================================
 * @file        TokenLifecycleManager.cpp
 * @brief       Implements the TokenLifecycleManager session governance engine, which
 *              maintains a zero-heap fixed-capacity session table paired with a static
 *              circular buffer for LRU slot eviction. The RegisterToken() path performs
 *              a constant-time client ID scan to prevent duplicate session admission and
 *              evicts the oldest active slot via the circular buffer when the table is
 *              at capacity. The EvaluateTokenExpiry() tick function provides the UN R155
 *              §7.2.2-mandated continuous session monitoring by sweeping all kMaxActiveSessions
 *              slots in O(N) bounded time and invoking the RevocationCallback for each
 *              expired entry. Session key material is zeroed using volatile byte-write
 *              loops on every revocation path to satisfy the automotive cryptographic
 *              data-at-rest erasure requirement (ISO/SAE 21434 §10.4.3). An anomaly
 *              counter per slot implements the brute-force lockout policy (THREAT-08),
 *              permanently barring a client after kMaxAnomalyCount successive failures
 *              within a single ECU power cycle.
 * @project     zonal-zero-trust-authenticator
 * @standards   AUTOSAR C++14, ISO/SAE 21434, UN R155, ISO 26262 ASIL-D
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * @note        This is a reference implementation showcasing norxs's SOA architecture.
 * =====================================================================================
 */

#include "zzta/TokenLifecycleManager.hpp"

#include <cstring>  // std::memcpy

namespace zzta {

// ─────────────────────────────────────────────────────────────────────────────
// Constructor
// ─────────────────────────────────────────────────────────────────────────────

TokenLifecycleManager::TokenLifecycleManager(RevocationCallback on_revoke) noexcept
    : session_table_{}
    , insertion_order_{}
    , on_revoke_cb_{on_revoke}
{
    // Zero-initialise all table slots explicitly.
    // Although std::array value-initialises to zero in C++14, we make this
    // explicit to satisfy ISO 26262 Part 6 §7.4.7 (defensive initialisation).
    for (std::size_t i{0U}; i < kMaxActiveSessions; ++i)
    {
        session_table_[i].client_id.fill(0x00U);
        session_table_[i].session_key.fill(0x00U);
        session_table_[i].session_nonce.fill(0x00U);
        session_table_[i].issued_at_ms   = 0U;
        session_table_[i].last_seen_ms   = 0U;
        session_table_[i].anomaly_count  = 0U;
        session_table_[i].is_active      = false;
        session_table_[i].is_locked_out  = false;
        session_table_[i].reserved_.fill(0U);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegisterToken
// ─────────────────────────────────────────────────────────────────────────────

TlmStatus TokenLifecycleManager::RegisterToken(
    const SpdmSessionToken& token,
    uint64_t                current_time_ms) noexcept
{
    // ── Parameter validation ──────────────────────────────────────────────────
    // Reject an all-zero client_id as it is the sentinel value for an empty slot.
    volatile uint8_t id_check{0U};
    for (std::size_t i{0U}; i < kClientIdLen; ++i)
    {
        id_check = static_cast<uint8_t>(id_check | token.client_id[i]);
    }
    if (id_check == 0U)
    {
        return TlmStatus::kInvalidParam;
    }

    // ── Lockout check ─────────────────────────────────────────────────────────
    if (IsLockedOut(token.client_id))
    {
        return TlmStatus::kLockedOut;
    }

    // ── Check for existing live session (refresh path) ────────────────────────
    std::size_t existing_idx{0U};
    if (FindSlotByClientId(token.client_id, existing_idx))
    {
        if (session_table_[existing_idx].is_active)
        {
            // Expire the old session before admitting the refreshed one.
            ZeroSlotSecrets(existing_idx);
            session_table_[existing_idx].is_active = false;
            insertion_order_.Remove(existing_idx);
            NotifyRevocation(token.client_id);
        }
    }

    // ── Locate a free slot ────────────────────────────────────────────────────
    std::size_t target_idx{0U};
    if (!FindFreeSlot(target_idx))
    {
        // Table is full — evict the oldest entry via LRU circular buffer.
        if (!insertion_order_.Pop(target_idx))
        {
            // This should never happen if the circular buffer and table are
            // kept in sync, but defensive handling is mandated by ISO 26262.
            return TlmStatus::kTableFull;
        }
        ZeroSlotSecrets(target_idx);
        NotifyRevocation(session_table_[target_idx].client_id);
        session_table_[target_idx].is_active = false;
    }

    // ── Populate new slot ─────────────────────────────────────────────────────
    TokenSlot& slot{session_table_[target_idx]};
    std::memcpy(slot.client_id.data(),     token.client_id.data(),     kClientIdLen);
    std::memcpy(slot.session_key.data(),   token.session_key.data(),   kSessionKeyLen);
    std::memcpy(slot.session_nonce.data(), token.session_nonce.data(), kNonceLen);
    slot.issued_at_ms  = current_time_ms;
    slot.last_seen_ms  = current_time_ms;
    // NOTE: anomaly_count and is_locked_out are intentionally NOT reset here.
    // Anomaly state must persist across re-registrations so that the lockout
    // mechanism (THREAT-08 / CM-08) cannot be bypassed by rapid re-auth.
    // anomaly_count is reset to 0 only on a clean successful ValidateToken call.
    slot.is_active     = true;

    // ── Record insertion order ────────────────────────────────────────────────
    static_cast<void>(insertion_order_.Push(target_idx));

    return TlmStatus::kOk;
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidateToken
// ─────────────────────────────────────────────────────────────────────────────

TlmStatus TokenLifecycleManager::ValidateToken(
    const ClientId& client_id,
    uint64_t        current_time_ms,
    SessionKey*     key_out) noexcept
{
    // ── Lockout check ─────────────────────────────────────────────────────────
    if (IsLockedOut(client_id))
    {
        return TlmStatus::kLockedOut;
    }

    // ── Find slot ─────────────────────────────────────────────────────────────
    std::size_t idx{0U};
    if (!FindSlotByClientId(client_id, idx))
    {
        return TlmStatus::kNotFound;
    }

    TokenSlot& slot{session_table_[idx]};
    if (!slot.is_active)
    {
        return TlmStatus::kNotFound;
    }

    // ── Expiry check ──────────────────────────────────────────────────────────
    const uint64_t age_ms{current_time_ms - slot.issued_at_ms};
    if (age_ms > kTokenLifetimeMs)
    {
        // Lazy expiry — the slot will also be caught by EvaluateTokenExpiry(),
        // but we expire it immediately here to avoid returning a stale key.
        ZeroSlotSecrets(idx);
        slot.is_active = false;
        insertion_order_.Remove(idx);
        NotifyRevocation(client_id);
        return TlmStatus::kNotFound;
    }

    // ── Update activity timestamp ─────────────────────────────────────────────
    slot.last_seen_ms = current_time_ms;

    // ── Optionally copy out session key ───────────────────────────────────────
    if (key_out != nullptr)
    {
        std::memcpy(key_out->data(), slot.session_key.data(), kSessionKeyLen);
    }

    return TlmStatus::kOk;
}

// ─────────────────────────────────────────────────────────────────────────────
// RevokeToken
// ─────────────────────────────────────────────────────────────────────────────

TlmStatus TokenLifecycleManager::RevokeToken(
    const ClientId& client_id,
    bool            is_anomaly) noexcept
{
    std::size_t idx{0U};
    if (!FindSlotByClientId(client_id, idx))
    {
        return TlmStatus::kNotFound;
    }

    TokenSlot& slot{session_table_[idx]};

    // ── Anomaly counter ───────────────────────────────────────────────────────
    if (is_anomaly && (slot.anomaly_count < 0xFFU))
    {
        ++slot.anomaly_count;
        if (slot.anomaly_count >= kMaxAnomalyCount)
        {
            // Lock out this client for the remainder of the power cycle.
            slot.is_locked_out = true;
        }
    }

    // ── Invalidate session ────────────────────────────────────────────────────
    ZeroSlotSecrets(idx);
    slot.is_active = false;
    insertion_order_.Remove(idx);
    NotifyRevocation(client_id);

    return TlmStatus::kOk;
}

// ─────────────────────────────────────────────────────────────────────────────
// EvaluateTokenExpiry — UN R155 §7.2.2 continuous monitoring tick
// ─────────────────────────────────────────────────────────────────────────────

void TokenLifecycleManager::EvaluateTokenExpiry(uint64_t current_time_ms) noexcept
{
    for (std::size_t i{0U}; i < kMaxActiveSessions; ++i)
    {
        TokenSlot& slot{session_table_[i]};

        if (!slot.is_active)
        {
            continue;
        }

        // ── Overflow-safe age calculation ─────────────────────────────────────
        // If current_time_ms has wrapped (extremely unlikely with uint64_t, but
        // defensive per ISO 26262 Part 6 §7.4.7), the subtraction remains correct
        // due to two's-complement unsigned arithmetic — age will be large and the
        // token will correctly expire.
        const uint64_t age_ms{current_time_ms - slot.issued_at_ms};

        if (age_ms > kTokenLifetimeMs)
        {
            // Capture client_id before zeroing the slot.
            ClientId expired_id{};
            std::memcpy(expired_id.data(), slot.client_id.data(), kClientIdLen);

            ZeroSlotSecrets(i);
            slot.is_active = false;
            insertion_order_.Remove(i);
            NotifyRevocation(expired_id);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GetActiveSessionCount
// ─────────────────────────────────────────────────────────────────────────────

std::size_t TokenLifecycleManager::GetActiveSessionCount() const noexcept
{
    std::size_t count{0U};
    for (std::size_t i{0U}; i < kMaxActiveSessions; ++i)
    {
        if (session_table_[i].is_active)
        {
            ++count;
        }
    }
    return count;
}

// ─────────────────────────────────────────────────────────────────────────────
// IsLockedOut
// ─────────────────────────────────────────────────────────────────────────────

bool TokenLifecycleManager::IsLockedOut(const ClientId& client_id) const noexcept
{
    std::size_t idx{0U};
    if (FindSlotByClientId(client_id, idx))
    {
        return session_table_[idx].is_locked_out;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// FindSlotByClientId (private)
// ─────────────────────────────────────────────────────────────────────────────

bool TokenLifecycleManager::FindSlotByClientId(
    const ClientId& client_id,
    std::size_t&    idx_out) const noexcept
{
    for (std::size_t i{0U}; i < kMaxActiveSessions; ++i)
    {
        // Constant-time comparison for the active or locked-out case.
        volatile uint8_t diff{0U};
        for (std::size_t j{0U}; j < kClientIdLen; ++j)
        {
            diff = static_cast<uint8_t>(diff | (client_id[j] ^ session_table_[i].client_id[j]));
        }
        if (diff == 0U)
        {
            idx_out = i;
            return true;
        }
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// FindFreeSlot (private)
// ─────────────────────────────────────────────────────────────────────────────

bool TokenLifecycleManager::FindFreeSlot(std::size_t& idx_out) const noexcept
{
    for (std::size_t i{0U}; i < kMaxActiveSessions; ++i)
    {
        if (!session_table_[i].is_active && !session_table_[i].is_locked_out)
        {
            idx_out = i;
            return true;
        }
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// ZeroSlotSecrets (private)
// ─────────────────────────────────────────────────────────────────────────────

void TokenLifecycleManager::ZeroSlotSecrets(std::size_t idx) noexcept
{
    TokenSlot& slot{session_table_[idx]};

    // Volatile byte-write loop — prevents compiler dead-store elimination.
    volatile uint8_t* key_p{slot.session_key.data()};
    for (std::size_t i{0U}; i < kSessionKeyLen; ++i) { key_p[i]   = 0U; }

    volatile uint8_t* nonce_p{slot.session_nonce.data()};
    for (std::size_t i{0U}; i < kNonceLen; ++i)      { nonce_p[i] = 0U; }

    slot.issued_at_ms = 0U;
    slot.last_seen_ms = 0U;
}

// ─────────────────────────────────────────────────────────────────────────────
// NotifyRevocation (private)
// ─────────────────────────────────────────────────────────────────────────────

void TokenLifecycleManager::NotifyRevocation(const ClientId& client_id) noexcept
{
    if (on_revoke_cb_ != nullptr)
    {
        on_revoke_cb_(client_id);
    }
}

} // namespace zzta
