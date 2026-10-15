#pragma once

#include "domain/conversation_types.hpp"
#include "domain/message_types.hpp"
#include "securecloud/messaging/v1/messaging.pb.h"

#include <chrono>
#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace securecloud::messaging::domain {

/// Device-specific encrypted delivery target for a message envelope (ADR-008, Design 5.3).
struct DeviceDeliveryTarget {
    UserId recipient_user_id;
    DeviceId recipient_device_id;
    std::string ciphertext_blob;
    std::vector<uint8_t> ephemeral_public_key;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> auth_tag;
    std::string algorithm{"XChaCha20-Poly1305"};

    auto operator<=>(const DeviceDeliveryTarget& other) const noexcept = default;
    bool operator==(const DeviceDeliveryTarget& other) const noexcept = default;
};

/// Strongly-typed domain command encapsulating a client message submission request.
struct MessageSubmissionCommand {
    UserId caller_user_id;
    DeviceId sender_device_id;
    ConversationId conversation_id;
    std::string client_idempotency_token;
    MessagePriority priority{MessagePriority::Normal};
    std::optional<std::chrono::system_clock::time_point> expires_at{std::nullopt};
    std::vector<DeviceDeliveryTarget> delivery_targets;

    auto operator<=>(const MessageSubmissionCommand& other) const noexcept = default;
    bool operator==(const MessageSubmissionCommand& other) const noexcept = default;
};

/// Result object returned by the submission validation engine.
struct SubmissionValidationResult {
    bool is_valid{true};
    std::string error_message;
    std::string field_name;
    v1::MessagingErrorCode error_code{v1::MESSAGING_ERROR_CODE_UNSPECIFIED};

    [[nodiscard]] static SubmissionValidationResult ok() noexcept {
        return SubmissionValidationResult{true, "", "", v1::MESSAGING_ERROR_CODE_UNSPECIFIED};
    }

    [[nodiscard]] static SubmissionValidationResult
    invalid(std::string field, std::string message,
            v1::MessagingErrorCode code = v1::MESSAGING_ERROR_CODE_UNSPECIFIED) {
        return SubmissionValidationResult{false, std::move(message), std::move(field), code};
    }

    [[nodiscard]] explicit operator bool() const noexcept { return is_valid; }
};

} // namespace securecloud::messaging::domain
