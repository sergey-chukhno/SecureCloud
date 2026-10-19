#include "util/zero_plaintext_guard.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <sstream>

namespace securecloud::messaging::util {

std::string ZeroPlaintextGuard::format_safe_submission_log(const domain::MessageSubmissionCommand& cmd) {
    std::ostringstream oss;
    oss << "[MSG_SUBMISSION] conv_id=" << cmd.conversation_id.to_string() << " sender_user=" << cmd.caller_user_id.str()
        << " sender_device=" << cmd.sender_device_id.str() << " priority=" << domain::to_string(cmd.priority)
        << " proto=" << static_cast<int32_t>(cmd.protocol_version) << " targets_count=" << cmd.delivery_targets.size()
        << " [targets:";

    for (size_t i = 0; i < cmd.delivery_targets.size(); ++i) {
        const auto& t = cmd.delivery_targets[i];
        oss << " (dev=" << t.recipient_device_id.str() << " user=" << t.recipient_user_id.str()
            << " algo=" << t.algorithm << " cipher_bytes=" << t.ciphertext_blob.size() << " iv_bytes=" << t.iv.size()
            << " tag_bytes=" << t.auth_tag.size() << " pubkey_bytes=" << t.ephemeral_public_key.size() << ")";
    }
    oss << "]";
    return oss.str();
}

std::string ZeroPlaintextGuard::format_safe_envelope_log(const domain::E2EMessageEnvelope& envelope) {
    std::ostringstream oss;
    oss << "[E2E_ENVELOPE] msg_id=" << envelope.message_id.to_string()
        << " conv_id=" << envelope.conversation_id.to_string() << " sender_user=" << envelope.sender_user_id.str()
        << " sender_device=" << envelope.sender_device_id.str()
        << " proto=" << static_cast<int32_t>(envelope.protocol_version)
        << " per_device_count=" << envelope.per_device_envelopes.size() << " [envelopes:";

    for (size_t i = 0; i < envelope.per_device_envelopes.size(); ++i) {
        const auto& env = envelope.per_device_envelopes[i];
        oss << " (dev=" << env.recipient_device_id.str() << " algo=" << domain::to_string(env.algorithm)
            << " cipher_bytes=" << env.ciphertext_blob.size() << " iv_bytes=" << env.iv.size()
            << " tag_bytes=" << env.auth_tag.size() << " pubkey_bytes=" << env.ephemeral_public_key.size() << ")";
    }
    oss << "]";
    return oss.str();
}

std::string ZeroPlaintextGuard::summarize_target(const domain::DeviceDeliveryTarget& target) {
    std::ostringstream oss;
    oss << "{recipient_user: \"" << target.recipient_user_id.str() << "\", recipient_device: \""
        << target.recipient_device_id.str() << "\", algorithm: \"" << target.algorithm
        << "\", ciphertext_bytes: " << target.ciphertext_blob.size() << ", iv_bytes: " << target.iv.size()
        << ", tag_bytes: " << target.auth_tag.size() << ", pubkey_bytes: " << target.ephemeral_public_key.size() << "}";
    return oss.str();
}

std::string ZeroPlaintextGuard::summarize_envelope(const domain::PerDeviceEnvelope& env) {
    std::ostringstream oss;
    oss << "{recipient_device: \"" << env.recipient_device_id.str() << "\", algorithm: \""
        << domain::to_string(env.algorithm) << "\", ciphertext_bytes: " << env.ciphertext_blob.size()
        << ", iv_bytes: " << env.iv.size() << ", tag_bytes: " << env.auth_tag.size()
        << ", pubkey_bytes: " << env.ephemeral_public_key.size() << "}";
    return oss.str();
}

std::string ZeroPlaintextGuard::sanitize_error_message(std::string_view raw_error) {
    if (raw_error.empty()) {
        return "";
    }

    // List of sensitive prefix identifiers to redact in error messages
    static constexpr std::array<std::string_view, 6> kSensitiveKeywords = {
        "ciphertext=", "key=", "auth_tag=", "iv=", "secret=", "payload="};

    std::string sanitized;
    sanitized.reserve(std::min(raw_error.size(), kMaxSanitizedErrorLength));

    // 1. Scrub non-printable characters and truncate at limit
    size_t inspected_len = std::min(raw_error.size(), kMaxSanitizedErrorLength);
    for (size_t i = 0; i < inspected_len; ++i) {
        unsigned char c = static_cast<unsigned char>(raw_error[i]);
        if (c >= 0x20 && c <= 0x7E) {
            sanitized.push_back(static_cast<char>(c));
        } else if (c == '\t' || c == '\n' || c == '\r') {
            sanitized.push_back(' ');
        } else {
            sanitized.push_back('?');
        }
    }

    if (raw_error.size() > kMaxSanitizedErrorLength) {
        sanitized += "... [TRUNCATED]";
    }

    // 2. Scan and redact sensitive keywords
    for (const auto& keyword : kSensitiveKeywords) {
        size_t pos = 0;
        while ((pos = sanitized.find(keyword, pos)) != std::string::npos) {
            size_t val_start = pos + keyword.size();
            size_t val_end = sanitized.find_first_of(" \t\n\r,;)}", val_start);
            if (val_end == std::string::npos) {
                val_end = sanitized.size();
            }
            sanitized.replace(val_start, val_end - val_start, kRedactedPlaceholder);
            pos = val_start + kRedactedPlaceholder.size();
        }
    }

    return sanitized;
}

} // namespace securecloud::messaging::util
