#pragma once

#include "domain/conversation_types.hpp"
#include "domain/envelope_types.hpp"
#include "domain/message_types.hpp"
#include "securecloud/messaging/v1/messaging.pb.h"
#include "service/messaging_caller_context.hpp"
#include "service/protocol_version_policy.hpp"
#include "service/recipient_device_resolution_service.hpp"

#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::messaging::service {

/**
 * @brief Detailed outcome of complete E2E envelope validation.
 */
struct EnvelopeValidationResult {
    bool is_valid{false};
    v1::MessagingErrorCode error_code{v1::MESSAGING_ERROR_CODE_UNSPECIFIED};
    std::string error_message{};
    std::vector<domain::DeviceId> omitted_device_ids{};

    auto operator<=>(const EnvelopeValidationResult& other) const noexcept = default;
    bool operator==(const EnvelopeValidationResult& other) const noexcept = default;
};

/**
 * @brief Authoritative E2E Message Envelope Security, Integrity, and Anti-Plaintext Validator.
 *
 * Enforces the 5 critical security rules (ADR-008, MSG-006) on incoming message submissions:
 * 1. Sender Context Integrity: matches caller context to prevent spoofing.
 * 2. Protocol Version Whitelist: rejects unapproved/downgraded protocols.
 * 3. Recipient & Device Integrity: validates active participant membership and enrolled devices.
 * 4. Cryptographic Bounds: enforces IV, auth tag, ephemeral key, and payload size bounds.
 * 5. Anti-Plaintext Guard: detects and rejects accidental/malicious unencrypted ASCII/JSON payloads.
 */
class E2EEnvelopeValidator {
  public:
    explicit E2EEnvelopeValidator(std::shared_ptr<RecipientDeviceResolutionService> resolution_service);

    /**
     * @brief Performs complete validation of an E2E message envelope against caller context
     *        and conversation participant topology.
     *
     * @param envelope The top-level E2EMessageEnvelope to validate.
     * @param caller_context Authenticated caller context extracted from gRPC metadata.
     * @param conversation_participants Active participant user IDs in the target conversation.
     * @param enforce_completeness Whether active recipient devices must not be omitted.
     * @return EnvelopeValidationResult indicating success or specific error details.
     */
    [[nodiscard]] EnvelopeValidationResult validate(const domain::E2EMessageEnvelope& envelope,
                                                    const MessagingCallerContext& caller_context,
                                                    const std::vector<domain::UserId>& conversation_participants,
                                                    bool enforce_completeness = false) const;

    /**
     * @brief Evaluates whether a raw byte buffer exhibits characteristics of unencrypted
     *        ASCII or structured JSON plaintext rather than pseudorandom ciphertext.
     *
     * Inspects a bounded prefix sample (up to 256 bytes) in sub-microsecond time.
     *
     * @param payload Byte buffer to inspect.
     * @return true if payload is suspected unencrypted plaintext; false if genuine ciphertext.
     */
    [[nodiscard]] static bool is_suspected_unencrypted_plaintext(std::string_view payload) noexcept;

  private:
    std::shared_ptr<RecipientDeviceResolutionService> resolution_service_;
};

} // namespace securecloud::messaging::service
