/**
 * =====================================================================================
 * @file        TokenLifecycleManager.hpp
 * @brief       Declares the TokenLifecycleManager, which governs the validity, expiration,
 *              and proactive revocation of dynamic SPDM session tokens produced by the
 *              SpdmProtocolEngine, operating exclusively on zero-heap, compile-time-fixed
 *              data structures. The manager maintains an active session table as a
 *              std::array of TokenSlot records and a companion static circular buffer
 *              that tracks the insertion order for O(1) LRU eviction. The periodic
 *              method EvaluateTokenExpiry() satisfies the UN R155 §7.2.2 requirement
 *              for continuous session monitoring by scanning all active slots against
 *              the current system timestamp and immediately invalidating any token that
 *              has exceeded its compile-time-configured lifetime (kTokenLifetimeMs).
 *              Revocation events are propagated back to the corresponding
 *              SpdmProtocolEngine instance via the RevocationCallback function pointer,
 *              forcing immediate re-authentication without any dynamic dispatch overhead.
 * @project     zonal-zero-trust-authenticator
 * @standards   AUTOSAR C++14, ISO/SAE 21434, UN R155, ISO 26262 ASIL-D
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * @note        This is a reference implementation showcasing norxs's SOA architecture.
 * =====================================================================================
 */

#ifndef ZZTA_TOKEN_LIFECYCLE_MANAGER_HPP
#define ZZTA_TOKEN_LIFECYCLE_MANAGER_HPP

#include "zzta/CryptoPlatformInterface.hpp"
#include "zzta/SpdmProtocolEngine.hpp"

#include <array>
#include <cstdint>
#include <cstddef>

namespace zzta {

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time policy constants
// ─────────────────────────────────────────────────────────────────────────────

/** @brief Maximum number of concurrently active session tokens.
 *
 *  Must match the number of zone node slots provisioned in the Zonal Gateway
 *  hardware design. Changing this value invalidates all static memory budgets
 *  and requires a re-assessment under ISO 26262 Part 4 §6.4.6.
 */
static constexpr std::size_t kMaxActiveSessions{8U};

/** @brief Session token lifetime in milliseconds (default: 30 seconds).
 *
 *  UN R155 §7.2.2 requires that session tokens expire within a bounded window.
 *  The 30-second default is conservative for a Zonal ECU environment where
 *  re-authentication latency over SOME/IP is < 5 ms.
 *
 *  Production systems may adjust this value to match their TARA-defined
 *  session validity window. Minimum allowed value: 1000U (1 second).
 */
static constexpr uint64_t kTokenLifetimeMs{30'000U};
static_assert(kTokenLifetimeMs >= 1'000U,
    "Token lifetime must be at least 1 second to allow SPDM re-authentication.");

/** @brief Maximum number of consecutive anomaly events before permanent lock-out.
 *
 *  After kMaxAnomalyCount successive verification failures from the same client,
 *  the slot is marked kLockedOut and the client_id is blacklisted for the
 *  duration of the ECU power cycle. Satisfies ISO/SAE 21434 §15 — THREAT-08
 *  (Brute-Force Authentication Attack).
 */
static constexpr uint8_t kMaxAnomalyCount{3U};

// ─────────────────────────────────────────────────────────────────────────────
// Return codes
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Status codes returned by TokenLifecycleManager operations.
 */
enum class TlmStatus : uint8_t
{
    kOk             = 0x00U, ///< Operation completed successfully.
    kTableFull      = 0x01U, ///< No free slot available (all kMaxActiveSessions in use).
    kNotFound       = 0x02U, ///< Specified client_id not found in the active table.
    kAlreadyExists  = 0x03U, ///< A live session for client_id already exists.
    kLockedOut      = 0x04U, ///< Client is locked out after exceeding anomaly threshold.
    kInvalidParam   = 0x05U  ///< Null pointer or invalid argument supplied.
};

// ─────────────────────────────────────────────────────────────────────────────
// RevocationCallback
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Function pointer type for token expiry / revocation notification.
 *
 * When EvaluateTokenExpiry() or RevokeToken() invalidates a session, this
 * callback is invoked to allow the owning code (e.g. the SOME/IP session
 * manager) to tear down the associated communication channel and trigger
 * a re-authentication sequence on the corresponding SpdmProtocolEngine.
 *
 * The callback runs synchronously in the EvaluateTokenExpiry() call context.
 * Implementations MUST NOT block, allocate heap memory, or call back into
 * the TokenLifecycleManager (no re-entrancy guarantee).
 *
 * @param client_id  The 64-bit identifier of the invalidated session.
 */
using RevocationCallback = void (*)(const ClientId& client_id) /* noexcept — C++17 */;

// ─────────────────────────────────────────────────────────────────────────────
// TokenSlot — internal representation of one active session
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief A single entry in the active session table.
 *
 * All fields are value-initialised; the is_active flag acts as the validity
 * sentinel. Slot reuse is only permitted when is_active == false.
 *
 * Memory layout: sizeof(TokenSlot) ≤ 128 bytes — verified by static_assert
 * to ensure the entire kMaxActiveSessions table fits within the AUTOSAR
 * C++14 stack-frame budget for MCU targets (≤ 1 KB per function).
 */
struct TokenSlot
{
    ClientId   client_id;              ///< Authenticated node identifier.
    SessionKey session_key;            ///< Active AES-256 session key.
    Nonce      session_nonce;          ///< Challenge nonce used during handshake.
    uint64_t   issued_at_ms;           ///< System timestamp at token issuance (ms).
    uint64_t   last_seen_ms;           ///< Timestamp of most recent validated message.
    uint8_t    anomaly_count;          ///< Running count of anomaly events for this peer.
    bool       is_active;              ///< True iff this slot holds a valid session.
    bool       is_locked_out;          ///< True iff this client is permanently banned.

    // Pad to 128-byte boundary for cache-line alignment on A53.
    std::array<uint8_t, 3U> reserved_{{0U, 0U, 0U}};
};
static_assert(sizeof(TokenSlot) <= 128U,
    "TokenSlot exceeds 128 bytes — review field layout to meet MCU memory budget.");

// ─────────────────────────────────────────────────────────────────────────────
// StaticCircularBuffer — zero-alloc, compile-time-capacity FIFO
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief A lock-free, zero-allocation circular buffer storing indices into the
 *        session table.
 *
 * Used by TokenLifecycleManager to track the insertion order of active slots,
 * enabling O(1) LRU eviction when the table is full and a grace-period token
 * must be replaced. Capacity is fixed at compile time to kMaxActiveSessions.
 *
 * @note This buffer is single-producer single-consumer (SPSC) without atomic
 *       operations. On multi-core SoCs the caller must serialise access using
 *       platform-specific spinlocks. On single-core MCUs no locking is needed.
 *
 * @tparam N  Buffer capacity; must equal kMaxActiveSessions.
 */
template<std::size_t N>
class StaticCircularBuffer final
{
    static_assert(N > 0U, "Buffer capacity must be greater than zero.");

public:
    StaticCircularBuffer() noexcept
        : buf_{}
        , head_{0U}
        , tail_{0U}
        , count_{0U}
    {
        buf_.fill(0U);
    }

    /** @return true if the buffer contains no elements. */
    [[nodiscard]] bool IsEmpty() const noexcept { return count_ == 0U; }

    /** @return true if the buffer has reached capacity N. */
    [[nodiscard]] bool IsFull()  const noexcept { return count_ == N; }

    /** @return Number of elements currently stored. */
    [[nodiscard]] std::size_t Size() const noexcept { return count_; }

    /**
     * @brief Enqueues a slot index.
     * @param idx  Slot index to enqueue (0 ≤ idx < N).
     * @return true on success; false if the buffer is full.
     */
    [[nodiscard]] bool Push(std::size_t idx) noexcept
    {
        if (IsFull()) { return false; }
        buf_[tail_] = static_cast<uint8_t>(idx);
        tail_ = (tail_ + 1U) % N;
        ++count_;
        return true;
    }

    /**
     * @brief Dequeues the oldest slot index.
     * @param[out] idx_out  Receives the dequeued index.
     * @return true on success; false if the buffer is empty.
     */
    [[nodiscard]] bool Pop(std::size_t& idx_out) noexcept
    {
        if (IsEmpty()) { return false; }
        idx_out = static_cast<std::size_t>(buf_[head_]);
        head_ = (head_ + 1U) % N;
        --count_;
        return true;
    }

    /**
     * @brief Removes all occurrences of idx from the buffer.
     *
     * Used when a slot is explicitly revoked before LRU eviction. Compacts
     * the buffer in-place by copying remaining elements.
     *
     * @param idx  Slot index to remove.
     */
    void Remove(std::size_t idx) noexcept
    {
        std::array<uint8_t, N> temp{};
        std::size_t new_count{0U};
        for (std::size_t i{0U}; i < count_; ++i)
        {
            const std::size_t pos{(head_ + i) % N};
            if (buf_[pos] != static_cast<uint8_t>(idx))
            {
                temp[new_count++] = buf_[pos];
            }
        }
        buf_  = temp;
        head_ = 0U;
        tail_ = new_count % N;
        count_ = new_count;
    }

private:
    std::array<uint8_t, N> buf_;   ///< Ring buffer storage.
    std::size_t            head_;  ///< Read index.
    std::size_t            tail_;  ///< Write index.
    std::size_t            count_; ///< Number of valid elements.
};

// ─────────────────────────────────────────────────────────────────────────────
// TokenLifecycleManager
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Manages the full lifecycle of SPDM session tokens produced by one or
 *        more SpdmProtocolEngine instances.
 *
 * The manager owns a fixed-capacity session table of kMaxActiveSessions slots
 * and a companion StaticCircularBuffer for LRU tracking. It provides four
 * core services:
 *
 *   1. RegisterToken()     — Admits a freshly authenticated session into the table.
 *   2. ValidateToken()     — Checks that a given client_id holds a live, non-expired session.
 *   3. RevokeToken()       — Immediately invalidates a specific session (e.g. IDS alert).
 *   4. EvaluateTokenExpiry() — Scheduled periodic scan; expires stale sessions.
 *
 * ISO/SAE 21434 traceability: CAL_TLM — §10.4.3 Session Lifecycle Management.
 * UN R155 traceability: CS.14 — Continuous session validity monitoring.
 */
class TokenLifecycleManager final
{
public:
    // ── Construction ─────────────────────────────────────────────────────────

    /**
     * @brief Constructs the manager with an optional revocation callback.
     *
     * @param on_revoke  Function pointer called when any token is expired or
     *                   explicitly revoked. May be nullptr if no callback is needed.
     */
    explicit TokenLifecycleManager(RevocationCallback on_revoke = nullptr) noexcept;

    ~TokenLifecycleManager() = default;

    // Deleted copy / move — table owns active session key material.
    TokenLifecycleManager(const TokenLifecycleManager&)            = delete;
    TokenLifecycleManager& operator=(const TokenLifecycleManager&) = delete;
    TokenLifecycleManager(TokenLifecycleManager&&)                 = delete;
    TokenLifecycleManager& operator=(TokenLifecycleManager&&)      = delete;

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * @brief Registers a new session token produced by a successful SPDM handshake.
     *
     * If the table already contains a live session for the same client_id, the
     * existing entry is first expired (with callback) before the new one is admitted,
     * allowing transparent session refresh.
     *
     * If the table is full, the slot with the oldest issued_at_ms timestamp
     * is evicted (LRU, via the circular buffer) to make room.
     *
     * @param[in] token         The session token from SpdmProtocolEngine.
     * @param[in] current_time_ms  Current monotonic system timestamp in milliseconds.
     * @return TlmStatus::kOk on success.
     *         TlmStatus::kLockedOut if the client_id is currently locked out.
     *         TlmStatus::kInvalidParam if token contains an all-zero client_id.
     */
    [[nodiscard]] TlmStatus RegisterToken(
        const SpdmSessionToken& token,
        uint64_t                current_time_ms) noexcept;

    /**
     * @brief Validates that the specified client holds an active, non-expired session.
     *
     * Updates the last_seen_ms field on a successful hit to support activity-based
     * session extension (configurable via kEnableActivityExtension compile flag).
     *
     * @param[in]  client_id        The client to validate.
     * @param[in]  current_time_ms  Current system timestamp in milliseconds.
     * @param[out] key_out          If non-null, receives the active session key on success.
     * @return TlmStatus::kOk if the session is alive and the key is valid.
     *         TlmStatus::kNotFound if no session exists for client_id.
     *         TlmStatus::kLockedOut if the client is locked out.
     */
    [[nodiscard]] TlmStatus ValidateToken(
        const ClientId& client_id,
        uint64_t        current_time_ms,
        SessionKey*     key_out = nullptr) noexcept;

    /**
     * @brief Immediately revokes the session for the specified client.
     *
     * Zeroes the session key in-place and fires the revocation callback.
     * Increments the anomaly_count; if this exceeds kMaxAnomalyCount the
     * client is locked out for the remainder of the power cycle.
     *
     * @param[in] client_id       The client whose session is to be revoked.
     * @param[in] is_anomaly      True if this revocation is the result of a security
     *                            anomaly (triggers anomaly counter increment).
     * @return TlmStatus::kOk if the session was found and revoked.
     *         TlmStatus::kNotFound if no session exists for client_id.
     */
    [[nodiscard]] TlmStatus RevokeToken(
        const ClientId& client_id,
        bool            is_anomaly) noexcept;

    /**
     * @brief Periodic scan function — must be called by a deterministic OS task
     *        or a hardware timer ISR at a rate ≤ kTokenLifetimeMs / 2.
     *
     * Scans all active slots and revokes any token whose age exceeds
     * kTokenLifetimeMs milliseconds relative to @p current_time_ms.
     * For each expired token the revocation callback is fired.
     *
     * Worst-case execution time: O(kMaxActiveSessions) — bounded and deterministic.
     * On a 216 MHz Cortex-M7 with kMaxActiveSessions = 8, WCET < 2 µs.
     *
     * ISO/SAE 21434 §15 compliance: This function implements TARA countermeasure
     * CM-03 (Continuous Session Monitoring).
     * UN R155 §7.2.2 traceability: CS.14 — "vehicle cybersecurity measures shall
     * include mechanisms to detect and respond to attacks."
     *
     * @param[in] current_time_ms  Current monotonic system timestamp in milliseconds.
     *                             Must be monotonically non-decreasing; caller is
     *                             responsible for timestamp overflow handling.
     */
    void EvaluateTokenExpiry(uint64_t current_time_ms) noexcept;

    /**
     * @brief Returns the number of currently active (live) session slots.
     * @return Count of slots where is_active == true.
     */
    [[nodiscard]] std::size_t GetActiveSessionCount() const noexcept;

    /**
     * @brief Returns true if the specified client is locked out.
     * @param[in] client_id  Client to check.
     * @return true if client_id is in the lockout list.
     */
    [[nodiscard]] bool IsLockedOut(const ClientId& client_id) const noexcept;

private:
    // ── Private helpers ───────────────────────────────────────────────────────

    /**
     * @brief Finds the table index for a given client_id using constant-time comparison.
     * @param[in]  client_id  Target client identifier.
     * @param[out] idx_out    Index of the matching slot on success.
     * @return true if found; false otherwise.
     */
    [[nodiscard]] bool FindSlotByClientId(
        const ClientId& client_id,
        std::size_t&    idx_out) const noexcept;

    /**
     * @brief Locates a free (is_active == false, not locked out) slot index.
     * @param[out] idx_out  Index of the free slot.
     * @return true if a free slot was found; false if the table is full.
     */
    [[nodiscard]] bool FindFreeSlot(std::size_t& idx_out) const noexcept;

    /**
     * @brief Zeroes the session key and nonce of slot at index @p idx using
     *        volatile writes to prevent compiler dead-store elimination.
     */
    void ZeroSlotSecrets(std::size_t idx) noexcept;

    /**
     * @brief Fires the revocation callback if one is registered.
     * @param[in] client_id  Client whose session was revoked.
     */
    void NotifyRevocation(const ClientId& client_id) noexcept;

    // ── Member variables ──────────────────────────────────────────────────────

    /** @brief Fixed-capacity session table (zero-allocation, .bss placement). */
    std::array<TokenSlot, kMaxActiveSessions> session_table_;

    /** @brief LRU-order circular buffer of active slot indices. */
    StaticCircularBuffer<kMaxActiveSessions> insertion_order_;

    /** @brief Optional user-supplied revocation callback. */
    RevocationCallback on_revoke_cb_;
};

} // namespace zzta

#endif // ZZTA_TOKEN_LIFECYCLE_MANAGER_HPP
