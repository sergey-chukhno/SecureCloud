#include "service/e2e_envelope_validator.hpp"

#include <algorithm>
#include <cctype>

namespace securecloud::messaging::service {

E2EEnvelopeValidator::E2EEnvelopeValidator(std::shared_ptr<RecipientDeviceResolutionService> resolution_service)
    : resolution_service_(std::move(resolution_service)) {}

bool E2EEnvelopeValidator::is_suspected_unencrypted_plaintext(std::string_view payload) noexcept {
    if (payload.empty()) {
        return false;
    }

    // Inspect bounded prefix sample (up to 256 bytes) in sub-microsecond time
    const size_t sample_len = std::min<size_t>(payload.size(), 256);
    std::string_view sample = payload.substr(0, sample_len);

    // 1. Unambiguous structured JSON delimiter prefix detection
    // e.g. starts with '{"' or '[{' or '{"type"'
    size_t non_ws = 0;
    while (non_ws < sample.size() && std::isspace(static_cast<unsigned char>(sample[non_ws]))) {
        ++non_ws;
    }
    if (non_ws + 1 < sample.size()) {
        if (sample[non_ws] == '{' &&
            (sample[non_ws + 1] == '"' || sample[non_ws + 1] == ' ' || sample[non_ws + 1] == '\n')) {
            return true;
        }
        if (sample[non_ws] == '[' && (sample[non_ws + 1] == '{' || sample[non_ws + 1] == '"')) {
            return true;
        }
    }

    // 2. High printable ASCII ratio check for plain text
    // In genuine AEAD ciphertext, bytes are uniformly distributed across [0, 255].
    // Printable ASCII (0x20..0x7E + \r, \n, \t) accounts for 98/256 (~38.3%) of values.
    // If a sample of length >= 16 has >= 90% printable ASCII, it is statistically impossible
    // to be genuine random ciphertext (p < 10^-15 for 32B, p < 10^-40 for 128B).
    if (sample_len >= 16) {
        size_t printable_count = 0;
        for (char ch : sample) {
            auto uc = static_cast<unsigned char>(ch);
            if ((uc >= 0x20 && uc <= 0x7E) || uc == '\n' || uc == '\r' || uc == '\t') {
                ++printable_count;
            }
        }

        const double ratio = static_cast<double>(printable_count) / static_cast<double>(sample_len);
        if (ratio >= 0.90) {
            return true;
        }
    }

    return false;
}

EnvelopeValidationResult E2EEnvelopeValidator::validate(const domain::E2EMessageEnvelope& envelope,
                                                        const MessagingCallerContext& caller_context,
                                                        const std::vector<domain::UserId>& conversation_participants,
                                                        bool enforce_completeness) const {

    // ------------------------------------------------------------------------
    // Rule 1: Sender Context Integrity (Anti-Spoofing)
    // ------------------------------------------------------------------------
    if (caller_context.user_id() != envelope.sender_user_id.str()) {
        return EnvelopeValidationResult{
            .is_valid = false,
            .error_code = v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
            .error_message = "Sender user ID (" + envelope.sender_user_id.str() +
                             ") does not match authenticated caller context (" + caller_context.user_id() + ")",
            .omitted_device_ids = {},
        };
    }

    if (!caller_context.device_id().empty() && caller_context.device_id() != envelope.sender_device_id.str()) {
        return EnvelopeValidationResult{
            .is_valid = false,
            .error_code = v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED,
            .error_message = "Sender device ID (" + envelope.sender_device_id.str() +
                             ") does not match authenticated caller device context (" + caller_context.device_id() +
                             ")",
            .omitted_device_ids = {},
        };
    }

    // ------------------------------------------------------------------------
    // Rule 2: Protocol Version Whitelist (Fail-Closed Anti-Downgrade)
    // ------------------------------------------------------------------------
    if (!ProtocolVersionPolicy::is_supported_protocol_version(envelope.protocol_version)) {
        return EnvelopeValidationResult{
            .is_valid = false,
            .error_code = v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
            .error_message =
                "Unsupported or deprecated E2E protocol version: " + domain::to_string(envelope.protocol_version),
            .omitted_device_ids = {},
        };
    }

    // ------------------------------------------------------------------------
    // Rule 4 & Rule 5: Cryptographic Bounds & Anti-Plaintext Guard
    // ------------------------------------------------------------------------
    if (envelope.per_device_envelopes.empty()) {
        return EnvelopeValidationResult{
            .is_valid = false,
            .error_code = v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
            .error_message = "Envelope contains no per-device delivery targets",
            .omitted_device_ids = {},
        };
    }

    for (const auto& dev_env : envelope.per_device_envelopes) {
        if (!ProtocolVersionPolicy::is_supported_protocol_version(dev_env.protocol_version)) {
            return EnvelopeValidationResult{
                .is_valid = false,
                .error_code = v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                .error_message = "Unsupported E2E protocol version (" + domain::to_string(dev_env.protocol_version) +
                                 ") for target device: " + dev_env.recipient_device_id.str(),
                .omitted_device_ids = {},
            };
        }

        auto param_err = ProtocolVersionPolicy::validate_envelope_security(dev_env);
        if (param_err.has_value()) {
            return EnvelopeValidationResult{
                .is_valid = false,
                .error_code = (param_err->find("exceeds maximum") != std::string::npos)
                                  ? v1::MESSAGING_ERROR_CODE_PAYLOAD_TOO_LARGE
                                  : v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
                .error_message = param_err.value(),
                .omitted_device_ids = {},
            };
        }

        // Anti-plaintext heuristic guard
        if (is_suspected_unencrypted_plaintext(dev_env.ciphertext_blob)) {
            return EnvelopeValidationResult{
                .is_valid = false,
                .error_code = v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
                .error_message = "Unencrypted plaintext payload rejected by security policy "
                                 "(zero plaintext invariant violation) for device " +
                                 dev_env.recipient_device_id.str(),
                .omitted_device_ids = {},
            };
        }
    }

    // ------------------------------------------------------------------------
    // Rule 3: Recipient & Device Integrity (Auth Directory)
    // ------------------------------------------------------------------------
    if (!resolution_service_) {
        return EnvelopeValidationResult{
            .is_valid = false,
            .error_code = v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
            .error_message = "Recipient device resolution service is uninitialized",
            .omitted_device_ids = {},
        };
    }

    auto target_res = resolution_service_->validate_submission_targets(
        conversation_participants, envelope.per_device_envelopes, envelope.sender_device_id, envelope.sender_user_id,
        enforce_completeness);

    if (!target_res.is_valid) {
        return EnvelopeValidationResult{
            .is_valid = false,
            .error_code = target_res.error_code,
            .error_message = target_res.error_message,
            .omitted_device_ids = std::move(target_res.omitted_device_ids),
        };
    }

    return EnvelopeValidationResult{
        .is_valid = true,
        .error_code = v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
        .error_message = {},
        .omitted_device_ids = std::move(target_res.omitted_device_ids),
    };
}

} // namespace securecloud::messaging::service
