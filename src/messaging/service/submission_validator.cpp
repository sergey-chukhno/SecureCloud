#include "service/submission_validator.hpp"

#include <chrono>
#include <set>
#include <string_view>

namespace securecloud::messaging::service {

namespace {

[[nodiscard]] bool is_printable_ascii(std::string_view sv) noexcept {
    for (char c : sv) {
        auto uc = static_cast<unsigned char>(c);
        if (uc < 32 || uc > 126) {
            return false;
        }
    }
    return true;
}

} // namespace

domain::SubmissionValidationResult SubmissionValidator::validate(const domain::MessageSubmissionCommand& cmd) {
    // 1. Caller User ID validation
    if (cmd.caller_user_id.empty()) {
        return domain::SubmissionValidationResult::invalid("caller_user_id", "Caller user ID cannot be empty");
    }
    if (!domain::UserId::is_valid_format(cmd.caller_user_id.str())) {
        return domain::SubmissionValidationResult::invalid("caller_user_id",
                                                           "Caller user ID must be a valid UUID format");
    }

    // 2. Sender Device ID validation
    if (cmd.sender_device_id.empty()) {
        return domain::SubmissionValidationResult::invalid("sender_device_id", "Sender device ID cannot be empty");
    }
    if (cmd.sender_device_id.str().size() > kMaxDeviceIdLength) {
        return domain::SubmissionValidationResult::invalid("sender_device_id",
                                                           "Sender device ID exceeds maximum length of 128 characters");
    }
    if (!is_printable_ascii(cmd.sender_device_id.str())) {
        return domain::SubmissionValidationResult::invalid(
            "sender_device_id", "Sender device ID must contain only printable ASCII characters");
    }

    // 3. Conversation ID validation (must be non-nil RFC 9562 UUIDv7)
    if (cmd.conversation_id.is_nil()) {
        return domain::SubmissionValidationResult::invalid("conversation_id",
                                                           "Conversation ID must be a non-nil valid UUIDv7");
    }

    // 4. Client Idempotency Token validation
    if (cmd.client_idempotency_token.empty()) {
        return domain::SubmissionValidationResult::invalid("client_idempotency_token",
                                                           "Client idempotency token cannot be empty");
    }
    if (cmd.client_idempotency_token.size() > kMaxIdempotencyTokenLength) {
        return domain::SubmissionValidationResult::invalid(
            "client_idempotency_token", "Client idempotency token exceeds maximum length of 128 characters");
    }
    if (!is_printable_ascii(cmd.client_idempotency_token)) {
        return domain::SubmissionValidationResult::invalid(
            "client_idempotency_token", "Client idempotency token must contain only printable ASCII characters");
    }

    // 5. Expiration validation (optional field; if present, must be in future)
    if (cmd.expires_at.has_value() && *cmd.expires_at <= std::chrono::system_clock::now()) {
        return domain::SubmissionValidationResult::invalid("expires_at",
                                                           "Message expiration timestamp must be in the future",
                                                           v1::MESSAGING_ERROR_CODE_MESSAGE_EXPIRED);
    }

    // 6. Delivery Targets collection validation
    if (cmd.delivery_targets.empty()) {
        return domain::SubmissionValidationResult::invalid("delivery_targets",
                                                           "At least one delivery target must be provided");
    }
    if (cmd.delivery_targets.size() > kMaxDeliveryTargets) {
        return domain::SubmissionValidationResult::invalid("delivery_targets",
                                                           "Delivery targets exceed maximum limit of 256");
    }

    std::set<std::string> seen_device_ids;

    // 7. Per-target validation (ADR-008 Cryptographic Envelope)
    for (const auto& target : cmd.delivery_targets) {
        if (target.recipient_user_id.empty()) {
            return domain::SubmissionValidationResult::invalid("delivery_targets.recipient_user_id",
                                                               "Recipient user ID cannot be empty");
        }
        if (!domain::UserId::is_valid_format(target.recipient_user_id.str())) {
            return domain::SubmissionValidationResult::invalid("delivery_targets.recipient_user_id",
                                                               "Recipient user ID must be a valid UUID format");
        }
        if (target.recipient_device_id.empty()) {
            return domain::SubmissionValidationResult::invalid("delivery_targets.recipient_device_id",
                                                               "Recipient device ID cannot be empty");
        }
        if (target.recipient_device_id.str().size() > kMaxDeviceIdLength) {
            return domain::SubmissionValidationResult::invalid(
                "delivery_targets.recipient_device_id", "Recipient device ID exceeds maximum length of 128 characters");
        }
        if (!is_printable_ascii(target.recipient_device_id.str())) {
            return domain::SubmissionValidationResult::invalid(
                "delivery_targets.recipient_device_id",
                "Recipient device ID must contain only printable ASCII characters");
        }

        // Uniqueness check across delivery targets
        if (!seen_device_ids.insert(target.recipient_device_id.str()).second) {
            return domain::SubmissionValidationResult::invalid(
                "delivery_targets",
                "Duplicate delivery target detected for recipient device: " + target.recipient_device_id.str());
        }

        // ADR-008: Ciphertext blob validation
        if (target.ciphertext_blob.empty()) {
            return domain::SubmissionValidationResult::invalid("delivery_targets.ciphertext_blob",
                                                               "Ciphertext blob cannot be empty");
        }
        if (target.ciphertext_blob.size() > kMaxPayloadSizeBytes) {
            return domain::SubmissionValidationResult::invalid(
                "delivery_targets.ciphertext_blob", "Ciphertext blob exceeds maximum payload size limit of 16MB",
                v1::MESSAGING_ERROR_CODE_PAYLOAD_TOO_LARGE);
        }

        // ADR-008: Algorithm validation
        if (target.algorithm != "XChaCha20-Poly1305" && target.algorithm != "AES-256-GCM") {
            return domain::SubmissionValidationResult::invalid(
                "delivery_targets.algorithm", "Unsupported cryptographic algorithm: " + target.algorithm);
        }

        // ADR-008: Auth tag validation (minimum 16 bytes)
        if (target.auth_tag.size() < kMinAuthTagSize) {
            return domain::SubmissionValidationResult::invalid("delivery_targets.auth_tag",
                                                               "Authentication tag must be at least 16 bytes");
        }

        // ADR-008: IV size validation
        if (target.algorithm == "XChaCha20-Poly1305" && target.iv.size() < kMinXChaChaIvSize) {
            return domain::SubmissionValidationResult::invalid(
                "delivery_targets.iv", "Initialization vector (IV) for XChaCha20-Poly1305 must be at least 24 bytes");
        }
        if (target.algorithm == "AES-256-GCM" && target.iv.size() < kMinAesGcmIvSize) {
            return domain::SubmissionValidationResult::invalid(
                "delivery_targets.iv", "Initialization vector (IV) for AES-256-GCM must be at least 12 bytes");
        }

        // ADR-008: Ephemeral public key validation
        if (target.ephemeral_public_key.empty()) {
            return domain::SubmissionValidationResult::invalid("delivery_targets.ephemeral_public_key",
                                                               "Ephemeral public key cannot be empty");
        }
    }

    return domain::SubmissionValidationResult::ok();
}

} // namespace securecloud::messaging::service
