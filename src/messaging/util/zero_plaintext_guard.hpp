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
 * 4. Strict validation of outbound audit metadata payloads (AUDIT-014).
 */
class ZeroPlaintextGuard {
  public:
    static constexpr std::string_view kRedactedPlaceholder = "[REDACTED]";
    static constexpr size_t kMaxSanitizedErrorLength = 512;
    static constexpr size_t kMaxAuditPayloadBytes = 8192;

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

    /**
     * @brief Validates an outbound audit metadata JSON payload against Zero-Plaintext and
     *        Zero-Secret invariants (ADR-008 / AUDIT-014).
     *
     * Throws std::logic_error if the payload is not a valid JSON object, exceeds size bounds,
     * contains raw binary/control bytes, or includes forbidden cryptographic/secret keys or values.
     */
    static void validate_audit_payload(std::string_view payload_json);

    /**
     * @brief Non-throwing variant of validate_audit_payload().
     */
    [[nodiscard]] static bool is_safe_audit_payload(std::string_view payload_json,
                                                    std::string* violation_reason = nullptr) noexcept;
};

} // namespace securecloud::messaging::util