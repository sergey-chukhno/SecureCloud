#pragma once

#include "domain/submission_types.hpp"

#include <cstddef>

namespace securecloud::messaging::service {

/**
 * @brief Input validation engine for message submission requests.
 *
 * Enforces contract rules (MSG-002), ADR-008 cryptographic standards,
 * and delivery target constraints before any persistence operations occur.
 */
class SubmissionValidator {
  public:
    static constexpr std::size_t kMaxIdempotencyTokenLength = 128;
    static constexpr std::size_t kMaxDeviceIdLength = 128;
    static constexpr std::size_t kMaxDeliveryTargets = 256;
    static constexpr std::size_t kMinAuthTagSize = 16;
    static constexpr std::size_t kMinAesGcmIvSize = 12;
    static constexpr std::size_t kMinXChaChaIvSize = 24;
    static constexpr std::size_t kMaxPayloadSizeBytes = 16 * 1024 * 1024; // 16 MB

    /**
     * @brief Validates the syntactic and cryptographic integrity of a MessageSubmissionCommand.
     *
     * @param cmd The submission command to validate.
     * @return SubmissionValidationResult Ok if valid, or Invalid with field name and descriptive error.
     */
    [[nodiscard]] static domain::SubmissionValidationResult validate(const domain::MessageSubmissionCommand& cmd);
};

} // namespace securecloud::messaging::service
