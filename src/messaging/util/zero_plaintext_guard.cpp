#include "util/zero_plaintext_guard.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>

namespace securecloud::messaging::util {

namespace {

[[nodiscard]] std::string to_lower_ascii(std::string_view input) {
    std::string out;
    out.reserve(input.size());
    for (unsigned char ch : input) {
        out.push_back(static_cast<char>(std::tolower(ch)));
    }
    return out;
}

[[nodiscard]] bool is_forbidden_audit_key(std::string_view key) {
    if (key.empty()) {
        return true;
    }
    const std::string lower = to_lower_ascii(key);

    if (lower == "iv" || lower.starts_with("iv_") || lower.ends_with("_iv")) {
        return true;
    }
    if (lower == "key" || lower.ends_with("_key") || lower.ends_with("_keys")) {
        return true;
    }

    static constexpr std::array<std::string_view, 17> kForbiddenKeySubstrings = {
        "ciphertext",    "ciphertext_blob", "ephemeral_public_key",
        "prekey",        "ratchet",         "secret",
        "private_key",   "token",           "plaintext",
        "password",      "passwd",          "auth_tag",
        "shared_secret", "session_key",     "signing_key",
        "credential",    "authorization",
    };

    for (std::string_view pattern : kForbiddenKeySubstrings) {
        if (lower.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool contains_long_encoded_blob(std::string_view value) noexcept {
    // Reject contiguous base64/hex payloads >= 128 chars indicative of encoded ciphertext or raw keys
    constexpr std::size_t kMaxContiguousEncodedRun = 128;
    std::size_t run = 0;
    for (unsigned char ch : value) {
        const bool is_encoded_char =
            std::isalnum(ch) != 0 || ch == '+' || ch == '/' || ch == '=' || ch == '-' || ch == '_';
        if (is_encoded_char) {
            ++run;
            if (run >= kMaxContiguousEncodedRun) {
                return true;
            }
        } else {
            run = 0;
        }
    }
    return false;
}

[[nodiscard]] bool is_forbidden_audit_value(std::string_view value) {
    for (unsigned char ch : value) {
        if (ch < 0x20 && ch != '\t' && ch != '\n' && ch != '\r') {
            return true;
        }
        if (ch == 0x7F) {
            return true;
        }
    }

    if (contains_long_encoded_blob(value)) {
        return true;
    }

    const std::string lower = to_lower_ascii(value);
    if (lower.find("-----begin ") != std::string::npos || lower.find("bearer ") != std::string::npos ||
        lower.find("$argon2") != std::string::npos || lower.find("$2a$") != std::string::npos ||
        lower.find("$2b$") != std::string::npos || lower.find("$2y$") != std::string::npos) {
        return true;
    }

    if (value.starts_with("eyJ") && std::count(value.begin(), value.end(), '.') == 2) {
        return true;
    }

    return false;
}

bool inspect_json_node(const nlohmann::json& node, std::string& violation) {
    if (node.is_object()) {
        for (const auto& [k, v] : node.items()) {
            if (is_forbidden_audit_key(k)) {
                violation = "Forbidden sensitive key in audit payload: '" + k + "'";
                return false;
            }
            if (!inspect_json_node(v, violation)) {
                return false;
            }
        }
        return true;
    }

    if (node.is_array()) {
        for (const auto& elem : node) {
            if (!inspect_json_node(elem, violation)) {
                return false;
            }
        }
        return true;
    }

    if (node.is_string()) {
        const std::string& str_val = node.get_ref<const std::string&>();
        if (is_forbidden_audit_value(str_val)) {
            violation = "Forbidden binary, secret, or encoded cryptographic blob in audit payload value";
            return false;
        }
    }

    return true;
}

} // namespace

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

bool ZeroPlaintextGuard::is_safe_audit_payload(std::string_view payload_json, std::string* violation_reason) noexcept {
    try {
        if (payload_json.empty()) {
            if (violation_reason != nullptr) {
                *violation_reason = "Audit payload_json must not be empty";
            }
            return false;
        }
        if (payload_json.size() > kMaxAuditPayloadBytes) {
            if (violation_reason != nullptr) {
                *violation_reason = "Audit payload_json exceeds maximum allowed size";
            }
            return false;
        }

        for (unsigned char ch : payload_json) {
            if (ch < 0x20 && ch != '\t' && ch != '\n' && ch != '\r') {
                if (violation_reason != nullptr) {
                    *violation_reason = "Raw binary control bytes detected in audit payload_json";
                }
                return false;
            }
        }

        const nlohmann::json parsed = nlohmann::json::parse(payload_json);
        if (!parsed.is_object()) {
            if (violation_reason != nullptr) {
                *violation_reason = "Audit payload_json must be a JSON object";
            }
            return false;
        }

        std::string violation;
        if (!inspect_json_node(parsed, violation)) {
            if (violation_reason != nullptr) {
                *violation_reason = std::move(violation);
            }
            return false;
        }
        return true;
    } catch (const std::exception& ex) {
        if (violation_reason != nullptr) {
            *violation_reason = std::string("Invalid JSON in audit payload: ") + ex.what();
        }
        return false;
    }
}

void ZeroPlaintextGuard::validate_audit_payload(std::string_view payload_json) {
    std::string violation;
    if (!is_safe_audit_payload(payload_json, &violation)) {
        throw std::logic_error("ZeroPlaintextGuard audit violation: " + violation);
    }
}

} // namespace securecloud::messaging::util
