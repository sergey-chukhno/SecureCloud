#pragma once

#include "domain/envelope_types.hpp"
#include "domain/submission_types.hpp"

#include <string>
#include <string_view>

namespace securecloud::messaging::util {

/**
 * @brief Zero-Knowledge Plaintext & Cryptographic Key Redaction Guard.
 *
 * In accordance with ADR-008, SecureCloud enforces strict zero-knowledge principles:
 * the backend messaging servers never decrypt, inspect, or log plaintext message
 * content or cryptographic keys.
 *
 * This utility provides:
 * 1. Safe structured audit logging formatters that log only routing metadata and byte counts.
 * 2. Error message sanitization preventing sensitive payload or key leakage in gRPC/HTTP errors.
 * 3. Individual target and envelope summary formatters.
 */
class ZeroPlaintextGuard {
  public:
    static constexpr std::string_view kRedactedPlaceholder = "[REDACTED]";
    static constexpr size_t kMaxSanitizedErrorLength = 512;

    /**
     * @brief Formats a safe audit log string for a message submission command.
     *        Logs strictly metadata (conversation, sender, priority, target IDs, byte lengths, algorithms)
     *        and guarantees zero raw ciphertext or key material leakage.
     */
    [[nodiscard]] static std::string format_safe_submission_log(const domain::MessageSubmissionCommand& cmd);

    /**
     * @brief Formats a safe audit log string for an E2EMessageEnvelope.
     */
    [[nodiscard]] static std::string format_safe_envelope_log(const domain::E2EMessageEnvelope& envelope);

    /**
     * @brief Sanitizes error messages by scrubbing non-printable bytes and redacting
     *        any sensitive substrings (e.g. key dumps, raw ciphertexts, secret tokens).
     */
    [[nodiscard]] static std::string sanitize_error_message(std::string_view raw_error);

    /**
     * @brief Safe summary of an individual delivery target.
     */
    [[nodiscard]] static std::string summarize_target(const domain::DeviceDeliveryTarget& target);

    /**
     * @brief Safe summary of an individual per-device envelope.
     */
    [[nodiscard]] static std::string summarize_envelope(const domain::PerDeviceEnvelope& env);
};

} // namespace securecloud::messaging::util
