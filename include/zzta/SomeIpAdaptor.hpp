/**
 * =====================================================================================
 * @file        SomeIpAdaptor.hpp
 * @brief       Declares the SomeIpAdaptor class, which bridges the
 *              zonal-zero-trust-authenticator authentication framework to a
 *              concrete SOME/IP service-discovery and message transport backend
 *              (e.g. vsomeip, AUTOSAR ComM/SoAd, or NXP S32G LLCE). The adaptor
 *              owns a pool of up to kMaxZoneSlots SpdmProtocolEngine instances
 *              and one shared TokenLifecycleManager, and exposes four integration
 *              hooks that the host SOME/IP stack calls on specific SD lifecycle
 *              events: OnPeerOffered (new service advertisement), OnAuthRequest
 *              (incoming SPDM frame type 0x01), OnAuthResponse (incoming SPDM
 *              frame type 0x02), and OnSessionTick (periodic 15 s expiry timer).
 *              The adaptor enforces the complete norxs Zero-Trust policy — no
 *              SOME/IP application frame is forwarded until the corresponding
 *              TokenLifecycleManager slot is in state kOk. This file defines
 *              the interface only; the concrete implementation must be provided
 *              by the BSW integration team targeting each specific SOME/IP stack.
 * @project     zonal-zero-trust-authenticator
 * @standards   AUTOSAR C++14, ISO/SAE 21434, UN R155, AUTOSAR SWS_SomeIpTp,
 *              AUTOSAR SWS_SD, SOME/IP Protocol Specification AUTOSAR_PRS_SOMEIPProtocol
 * @author      norxs-lab
 * @copyright   (c) 2026 norxs Technology LLC. All rights reserved.
 * @note        This is a reference implementation showcasing norxs's SOA architecture.
 * =====================================================================================
 */

#ifndef ZZTA_SOMEIP_ADAPTOR_HPP
#define ZZTA_SOMEIP_ADAPTOR_HPP

#include "zzta/CryptoPlatformInterface.hpp"
#include "zzta/SpdmProtocolEngine.hpp"
#include "zzta/TokenLifecycleManager.hpp"
#include "zzta/ZztaVersion.hpp"

#include <array>
#include <cstdint>
#include <cstddef>

namespace zzta {

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time adaptor policy
// ─────────────────────────────────────────────────────────────────────────────

/** @brief Maximum concurrent zone node slots managed by this adaptor instance.
 *
 *  Must not exceed kMaxActiveSessions (TokenLifecycleManager) nor
 *  kMaxKnownPeers (SpdmProtocolEngine peer table).
 *  Production: set to the actual number of zone domains in the vehicle topology.
 */
static constexpr std::size_t kMaxZoneSlots{8U};
static_assert(kMaxZoneSlots <= kMaxActiveSessions,
    "kMaxZoneSlots must not exceed kMaxActiveSessions.");
static_assert(kMaxZoneSlots <= kMaxKnownPeers,
    "kMaxZoneSlots must not exceed kMaxKnownPeers.");

// ─────────────────────────────────────────────────────────────────────────────
// SOME/IP SPDM frame header (wire format)
// Overlaid on the SOME/IP payload after the standard 16-byte SOME/IP header.
// Service ID: 0xF0CA (norxs private range)
// Method  ID: 0x0001 = AUTH_REQUEST, 0x0002 = AUTH_RESPONSE, 0x0003 = CHALLENGE
// ─────────────────────────────────────────────────────────────────────────────

/** @brief SOME/IP method ID for SPDM authentication request frame. */
static constexpr uint16_t kSomeIpMethodIdAuthRequest{0x0001U};

/** @brief SOME/IP method ID for SPDM challenge (gateway → zone node). */
static constexpr uint16_t kSomeIpMethodIdChallenge{0x0002U};

/** @brief SOME/IP method ID for SPDM authentication response frame. */
static constexpr uint16_t kSomeIpMethodIdAuthResponse{0x0003U};

/** @brief SOME/IP service ID for the ZZTA authentication service. */
static constexpr uint16_t kSomeIpZztaServiceId{0xF0CAU};

/** @brief SOME/IP instance ID (single instance per gateway). */
static constexpr uint16_t kSomeIpZztaInstanceId{0x0001U};

// ─────────────────────────────────────────────────────────────────────────────
// AdaptorStatus — return codes for all adaptor-level operations
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Return codes for SomeIpAdaptor hook functions.
 *
 * These are distinct from SpdmStatus and TlmStatus to allow the host stack
 * to distinguish protocol errors from transport/routing errors.
 */
enum class AdaptorStatus : uint8_t
{
    kOk                = 0x00U, ///< Operation completed successfully.
    kUnknownPeer       = 0x01U, ///< Source client_id not in peer table.
    kSlotExhausted     = 0x02U, ///< All kMaxZoneSlots are occupied.
    kProtocolError     = 0x03U, ///< SPDM engine returned an error.
    kSessionError      = 0x04U, ///< TokenLifecycleManager returned an error.
    kInvalidFrame      = 0x05U, ///< Frame too short or malformed.
    kNotAuthenticated  = 0x06U, ///< Payload rejected — session not active.
    kLockedOut         = 0x07U, ///< Client is permanently locked out.
    kInvalidParam      = 0x08U  ///< Null pointer or zero-length buffer.
};

// ─────────────────────────────────────────────────────────────────────────────
// TransmitCallback — function pointer for sending frames back to zone nodes
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Function pointer type for sending a SOME/IP frame to a specific peer.
 *
 * Provided by the host SOME/IP stack during adaptor construction. The adaptor
 * calls this to transmit the CHALLENGE nonce to the requesting zone node after
 * a successful `OnAuthRequest()`.
 *
 * @param client_id   Destination zone node identifier (used to resolve IP/port).
 * @param method_id   SOME/IP method ID (e.g. kSomeIpMethodIdChallenge).
 * @param payload     Pointer to the frame payload bytes.
 * @param payload_len Number of bytes in payload.
 */
using TransmitCallback = void (*)(
    const ClientId& client_id,
    uint16_t        method_id,
    const uint8_t*  payload,
    std::size_t     payload_len); // noexcept on fn-ptr typedefs requires C++17

// ─────────────────────────────────────────────────────────────────────────────
// SlotState — internal per-zone-slot state
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Internal state record for one managed zone node slot.
 *
 * Each slot binds a `SpdmProtocolEngine` instance to the `client_id` of the
 * zone node currently occupying that slot. Slots are allocated on
 * `OnPeerOffered()` and freed when the session is revoked and `Reset()` is
 * called.
 */
struct ZoneSlotRecord
{
    ClientId client_id;     ///< Bound zone node identifier. All-zero = unoccupied.
    bool     is_occupied;   ///< True iff a peer is assigned to this slot.
};

// ─────────────────────────────────────────────────────────────────────────────
// SomeIpAdaptor
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Bridges the ZZTA authentication stack to the host SOME/IP transport.
 *
 * ## Integration Model
 *
 * The host SOME/IP stack calls the four hook functions below at the appropriate
 * points in the service-discovery and message-receive lifecycle:
 *
 * ```
 * SOME/IP SD "OfferService" received from zone node
 *   → SomeIpAdaptor::OnPeerOffered(client_id)
 *
 * SOME/IP message arrives, MethodId == kSomeIpMethodIdAuthRequest
 *   → SomeIpAdaptor::OnAuthRequest(raw_payload, len)
 *     → SpdmProtocolEngine::ProcessAuthRequest()
 *     → TransmitCallback(client_id, kSomeIpMethodIdChallenge, nonce, 32)
 *
 * SOME/IP message arrives, MethodId == kSomeIpMethodIdAuthResponse
 *   → SomeIpAdaptor::OnAuthResponse(raw_payload, len)
 *     → SpdmProtocolEngine::ProcessAuthResponse()
 *     → TokenLifecycleManager::RegisterToken()
 *
 * Every 15 seconds, OS timer fires
 *   → SomeIpAdaptor::OnSessionTick(monotonic_ms)
 *     → TokenLifecycleManager::EvaluateTokenExpiry()
 *
 * SOME/IP application message arrives (any method)
 *   → SomeIpAdaptor::IsSessionActive(client_id, now_ms, key_out)
 *     → TokenLifecycleManager::ValidateToken()
 *     → Host stack decrypts/verifies with AES-256-GCM key_out
 * ```
 *
 * ## Thread Safety
 *
 * This adaptor is **not** thread-safe. On a QNX AUTOSAR Adaptive platform,
 * the integrator must serialise all hook calls through a single thread or
 * protect them with a platform spinlock. On bare-metal M7, ISR serialisation
 * is provided by the single-core scheduler.
 *
 * ISO/SAE 21434 traceability: CAL_ADAPTOR — §10.4.4 Transport Integration.
 */
class SomeIpAdaptor final
{
public:
    // ── Construction ─────────────────────────────────────────────────────────

    /**
     * @brief Constructs the adaptor with all required dependencies.
     *
     * @param crypto_pal   Reference to the platform cryptographic provider.
     *                     Must outlive this adaptor.
     * @param peer_table   Pointer to the OEM-provisioned peer public key table.
     * @param peer_count   Number of valid entries in peer_table (≤ kMaxKnownPeers).
     * @param on_transmit  Callback for sending frames back to zone nodes. Must not be nullptr.
     * @param on_revoke    Optional callback fired when a session is expired or revoked.
     */
    explicit SomeIpAdaptor(
        CryptoPlatformInterface& crypto_pal,
        const KnownPeerEntry*    peer_table,
        std::size_t              peer_count,
        TransmitCallback         on_transmit,
        RevocationCallback       on_revoke = nullptr) noexcept;

    ~SomeIpAdaptor() = default;

    // Copy / move: deleted — adaptor owns engine array and TLM state.
    SomeIpAdaptor(const SomeIpAdaptor&)            = delete;
    SomeIpAdaptor& operator=(const SomeIpAdaptor&) = delete;
    SomeIpAdaptor(SomeIpAdaptor&&)                 = delete;
    SomeIpAdaptor& operator=(SomeIpAdaptor&&)      = delete;

    // ── SOME/IP SD lifecycle hooks ────────────────────────────────────────────

    /**
     * @brief Called when a SOME/IP SD "OfferService" is received from a zone node.
     *
     * Allocates an engine slot for the offering node. If all slots are occupied
     * the oldest session is evicted to make room (aligned with LRU policy of TLM).
     *
     * @param[in] client_id  64-bit identifier extracted from the SD payload.
     * @return AdaptorStatus::kOk on success.
     *         AdaptorStatus::kUnknownPeer if client_id is not in the peer table.
     *         AdaptorStatus::kLockedOut if the client is under anomaly lockout.
     */
    [[nodiscard]] AdaptorStatus OnPeerOffered(const ClientId& client_id) noexcept;

    /**
     * @brief Called when a SOME/IP message with MethodId == kSomeIpMethodIdAuthRequest
     *        is received from a zone node.
     *
     * Deserialises the `SpdmAuthRequest` from the raw payload, forwards it to the
     * matching `SpdmProtocolEngine`, and on success transmits the 32-byte challenge
     * nonce back to the zone node via `TransmitCallback`.
     *
     * @param[in] payload      Raw SOME/IP payload bytes (must be ≥ sizeof(SpdmAuthRequest)).
     * @param[in] payload_len  Byte count of payload.
     * @return AdaptorStatus::kOk on success.
     *         AdaptorStatus::kInvalidFrame if payload_len < sizeof(SpdmAuthRequest).
     *         AdaptorStatus::kUnknownPeer if no engine slot matches the client_id.
     *         AdaptorStatus::kProtocolError if the SPDM engine rejects the request.
     */
    [[nodiscard]] AdaptorStatus OnAuthRequest(
        const uint8_t* payload,
        std::size_t    payload_len) noexcept;

    /**
     * @brief Called when a SOME/IP message with MethodId == kSomeIpMethodIdAuthResponse
     *        is received from a zone node.
     *
     * Deserialises the `SpdmAuthResponse`, completes the handshake via the matching
     * `SpdmProtocolEngine`, and on success registers the derived session token with
     * the `TokenLifecycleManager`.
     *
     * @param[in] payload      Raw SOME/IP payload bytes (must be ≥ sizeof(SpdmAuthResponse)).
     * @param[in] payload_len  Byte count of payload.
     * @param[in] current_time_ms  Monotonic system timestamp used to stamp the token.
     * @return AdaptorStatus::kOk on success.
     *         AdaptorStatus::kInvalidFrame if payload_len < sizeof(SpdmAuthResponse).
     *         AdaptorStatus::kProtocolError if signature verification fails.
     *         AdaptorStatus::kSessionError if token registration fails.
     */
    [[nodiscard]] AdaptorStatus OnAuthResponse(
        const uint8_t* payload,
        std::size_t    payload_len,
        uint64_t       current_time_ms) noexcept;

    /**
     * @brief Called by the OS/RTOS periodic timer at a rate ≤ kTokenLifetimeMs / 2.
     *
     * Delegates to `TokenLifecycleManager::EvaluateTokenExpiry()`. Must be called
     * at least every 15 000 ms to satisfy UN R155 §7.2.2 continuous monitoring.
     *
     * @param[in] current_time_ms  Monotonic system timestamp in milliseconds.
     */
    void OnSessionTick(uint64_t current_time_ms) noexcept;

    // ── Application-layer session gate ────────────────────────────────────────

    /**
     * @brief Zero-trust session gate — called by the host stack for every inbound
     *        SOME/IP application frame before forwarding to the application layer.
     *
     * Returns kOk and optionally populates `key_out` with the active AES-256-GCM
     * session key if and only if the source client holds a live, non-expired session.
     * Any other result means the frame MUST be silently dropped.
     *
     * @param[in]  client_id        Source zone node identifier.
     * @param[in]  current_time_ms  Current monotonic timestamp.
     * @param[out] key_out          If non-null, receives the 256-bit session key on kOk.
     * @return AdaptorStatus::kOk if the session is active.
     *         AdaptorStatus::kNotAuthenticated if no live session exists.
     *         AdaptorStatus::kLockedOut if the client is locked out.
     */
    [[nodiscard]] AdaptorStatus IsSessionActive(
        const ClientId& client_id,
        uint64_t        current_time_ms,
        SessionKey*     key_out = nullptr) noexcept;

    /**
     * @brief Immediately revokes the session for the specified zone node.
     *
     * Called by an IDS agent, OTA orchestrator, or diagnostic routine to
     * forcibly terminate an active session. Sets `is_anomaly = true` which
     * increments the anomaly counter and may trigger lockout.
     *
     * @param[in] client_id  Zone node whose session is to be revoked.
     * @param[in] is_anomaly True if revocation is triggered by a security anomaly.
     * @return AdaptorStatus::kOk if the session was found and revoked.
     *         AdaptorStatus::kUnknownPeer if no session exists for client_id.
     */
    [[nodiscard]] AdaptorStatus RevokeSession(
        const ClientId& client_id,
        bool            is_anomaly) noexcept;

    // ── Diagnostics ───────────────────────────────────────────────────────────

    /**
     * @brief Returns the number of currently active authenticated sessions.
     * @return Count of live session tokens (0..kMaxZoneSlots).
     */
    [[nodiscard]] std::size_t GetActiveSessionCount() const noexcept;

    /**
     * @brief Returns the ZZTA component version word for UDS DID 0xF189 reporting.
     * @return Packed version (bits[23:16]=Major, bits[15:8]=Minor, bits[7:0]=Patch).
     */
    [[nodiscard]] static constexpr uint32_t GetVersionWord() noexcept
    {
        return kVersionWord;
    }

private:
    // ── Private helpers ───────────────────────────────────────────────────────

    /**
     * @brief Finds the engine slot index for a given client_id.
     * @param[in]  client_id  Target client identifier.
     * @param[out] slot_out   Slot index on success.
     * @return true if found; false otherwise.
     */
    [[nodiscard]] bool FindSlot(
        const ClientId& client_id,
        std::size_t&    slot_out) const noexcept;

    /**
     * @brief Finds a free (unoccupied) engine slot.
     * @param[out] slot_out  Index of the free slot.
     * @return true if a free slot exists; false if all occupied.
     */
    [[nodiscard]] bool FindFreeEngineSlot(std::size_t& slot_out) const noexcept;

    /**
     * @brief Internal revocation callback wired from TLM → engine pool.
     *
     * When TLM expires or revokes a session, this callback calls
     * `SpdmProtocolEngine::Revoke()` on the matching engine slot so that
     * the FSM state is immediately reset.
     *
     * @param client_id  The client whose session was revoked by TLM.
     */
    void HandleRevocation(const ClientId& client_id) noexcept;

    // ── Member variables ──────────────────────────────────────────────────────

    /** @brief Pool of SPDM engine instances — one per zone node slot. */
    std::array<SpdmProtocolEngine, kMaxZoneSlots> engines_;

    /** @brief Slot occupancy records — maps slot index to client_id. */
    std::array<ZoneSlotRecord, kMaxZoneSlots> slot_records_;

    /** @brief Shared session lifecycle manager for all zone slots. */
    TokenLifecycleManager tlm_;

    /** @brief Host stack transmit callback for sending challenges. */
    TransmitCallback on_transmit_;

    /** @brief Constructs SpdmProtocolEngine instances from shared PAL + peer table. */
    const KnownPeerEntry* peer_table_;
    std::size_t           peer_count_;
};

} // namespace zzta

#endif // ZZTA_SOMEIP_ADAPTOR_HPP
