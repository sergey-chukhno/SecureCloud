#include "auth/audit/auth_audit_mapper.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <nlohmann/json.hpp>
#include <stdexcept>

namespace securecloud::auth::audit {

namespace {

// Exact bounds aligned with securecloud::audit::domain::AuditEventValidationLimits (AUDIT-002)
constexpr std::size_t kMaxEventTypeLength = 64;
constexpr std::size_t kMaxInstanceLength = 64;
constexpr std::size_t kMaxActorIdLength = 128;
constexpr std::size_t kMaxTargetIdLength = 128;
constexpr std::size_t kMaxCorrelationIdLength = 64;
constexpr std::size_t kMaxCausationIdLength = 64;
constexpr std::size_t kMaxMetadataEntries = 50;
constexpr std::size_t kMaxMetadataKeyLength = 64;
constexpr std::size_t kMaxMetadataValueLength = 1024;

constexpr int64_t kMaxFutureSkewMs = 300LL * 1000LL;                    // 5 minutes
constexpr int64_t kMaxPastAgeMs = 24LL * 1095LL * 60LL * 60LL * 1000LL; // 36 months (1,095 days)

[[nodiscard]] std::string to_lower_ascii(std::string_view input) {
    std::string out;
    out.reserve(input.size());
    for (unsigned char ch : input) {
        out.push_back(static_cast<char>(std::tolower(ch)));
    }
    return out;
}

[[nodiscard]] bool is_hex_digit(char ch) noexcept {
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
}

/// Validates RFC 9562 UUIDv7 canonical representation: xxxxxxxx-xxxx-7xxx-[89ab]xxx-xxxxxxxxxxxx
[[nodiscard]] bool is_valid_uuid_v7(std::string_view value) noexcept {
    if (value.size() != 36) {
        return false;
    }
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') {
                return false;
            }
            continue;
        }
        if (!is_hex_digit(value[i])) {
            return false;
        }
    }
    if (value[14] != '7') {
        return false;
    }
    const char variant = static_cast<char>(std::tolower(static_cast<unsigned char>(value[19])));
    return variant == '8' || variant == '9' || variant == 'a' || variant == 'b';
}

/// Validates `auth.<domain>.<action>` namespace and character set.
[[nodiscard]] bool is_valid_auth_event_type(std::string_view event_type) noexcept {
    if (event_type.size() <= 5 || event_type.size() > kMaxEventTypeLength) {
        return false;
    }
    if (!event_type.starts_with("auth.")) {
        return false;
    }
    for (char ch : event_type) {
        const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-';
        if (!ok) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] ::securecloud::audit::v1::SeverityProto parse_severity(std::string_view sev) {
    if (sev == "INFO") {
        return ::securecloud::audit::v1::SEVERITY_INFO;
    }
    if (sev == "WARNING") {
        return ::securecloud::audit::v1::SEVERITY_WARNING;
    }
    if (sev == "SECURITY") {
        return ::securecloud::audit::v1::SEVERITY_SECURITY;
    }
    if (sev == "CRITICAL") {
        return ::securecloud::audit::v1::SEVERITY_CRITICAL;
    }
    throw std::invalid_argument("Invalid audit severity: " + std::string(sev));
}

[[nodiscard]] ::securecloud::audit::v1::ActorTypeProto parse_actor_type(std::string_view actor) {
    if (actor == "USER") {
        return ::securecloud::audit::v1::ACTOR_TYPE_USER;
    }
    if (actor == "DEVICE") {
        return ::securecloud::audit::v1::ACTOR_TYPE_DEVICE;
    }
    if (actor == "SERVICE") {
        return ::securecloud::audit::v1::ACTOR_TYPE_SERVICE;
    }
    if (actor == "SYSTEM") {
        return ::securecloud::audit::v1::ACTOR_TYPE_SYSTEM;
    }
    throw std::invalid_argument("Invalid audit actor_type: " + std::string(actor));
}

[[nodiscard]] ::securecloud::audit::v1::TargetTypeProto parse_target_type(std::string_view target) {
    if (target == "USER") {
        return ::securecloud::audit::v1::TARGET_TYPE_USER;
    }
    if (target == "DEVICE") {
        return ::securecloud::audit::v1::TARGET_TYPE_DEVICE;
    }
    if (target == "CONVERSATION") {
        return ::securecloud::audit::v1::TARGET_TYPE_CONVERSATION;
    }
    if (target == "FILE") {
        return ::securecloud::audit::v1::TARGET_TYPE_FILE;
    }
    if (target == "SERVICE") {
        return ::securecloud::audit::v1::TARGET_TYPE_SERVICE;
    }
    throw std::invalid_argument("Invalid audit target_type: " + std::string(target));
}

[[nodiscard]] std::string resolve_producer_instance(const AuthConfig& config) {
    if (!config.producer_instance.empty() && config.producer_instance != "auth-1") {
        return config.producer_instance;
    }
    if (!config.common.service_name.empty()) {
        return config.common.service_name;
    }
    return config.producer_instance.empty() ? "auth" : config.producer_instance;
}

} // namespace

AuthAuditMapper::AuthAuditMapper(std::string default_producer_instance)
    : default_producer_instance_(default_producer_instance.empty() ? "auth" : std::move(default_producer_instance)) {}

AuthAuditMapper::AuthAuditMapper(const AuthConfig& config)
    : default_producer_instance_(resolve_producer_instance(config)) {}

bool AuthAuditMapper::is_sensitive_metadata_key(std::string_view key) noexcept {
    if (key.empty()) {
        return true;
    }
    const std::string lower = to_lower_ascii(key);

    // Explicitly permitted non-secret reference metadata keys
    if (lower == "key_id" || lower == "signed_prekey_id" || lower == "key_fingerprint") {
        return false;
    }

    if (lower == "key") {
        return true;
    }

    static constexpr std::array<std::string_view, 25> kForbiddenSubstrings = {
        "password",    "passwd",        "pwd",         "secret",     "token",
        "credential",  "private_key",   "signing_key", "master_key", "encryption_key",
        "session_key", "symmetric_key", "api_key",     "apikey",     "recovery_code",
        "backup_code", "passphrase",    "mnemonic",    "seed",       "authorization",
        "cookie",      "password_hash", "secret_hash", "salt",       "plaintext",
    };

    for (std::string_view pattern : kForbiddenSubstrings) {
        if (lower.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool contains_embedded_jwt(std::string_view value) noexcept {
    std::size_t pos = 0;
    while ((pos = value.find("eyJ", pos)) != std::string_view::npos) {
        std::size_t end = pos;
        int dots = 0;
        while (end < value.size()) {
            const unsigned char ch = static_cast<unsigned char>(value[end]);
            const bool is_b64url = std::isalnum(ch) != 0 || ch == '-' || ch == '_' || ch == '=';
            if (ch == '.') {
                ++dots;
                ++end;
            } else if (is_b64url) {
                ++end;
            } else {
                break;
            }
        }
        if (dots == 2 && (end - pos) >= 20) {
            return true;
        }
        pos += 3;
    }
    return false;
}

[[nodiscard]] bool contains_sensitive_assignment(std::string_view lower) noexcept {
    static constexpr std::array<std::string_view, 14> kSensitiveKeys = {
        "password", "passwd",      "pwd",       "secret",        "token",         "refresh_token", "access_token",
        "api_key",  "private_key", "totp_code", "recovery_code", "authorization", "cookie",        "passphrase",
    };

    for (std::string_view key : kSensitiveKeys) {
        std::size_t pos = 0;
        while ((pos = lower.find(key, pos)) != std::string_view::npos) {
            std::size_t after = pos + key.size();
            while (after < lower.size() && (lower[after] == ' ' || lower[after] == '\t')) {
                ++after;
            }
            if (after < lower.size() && (lower[after] == '=' || lower[after] == ':')) {
                return true;
            }
            pos += key.size();
        }
    }
    return false;
}

std::string AuthAuditMapper::sanitize_metadata_value(std::string_view value) {
    const std::string lower = to_lower_ascii(value);

    // Detect Bearer headers, PEM private keys, password hashes, credential assignments, or embedded JWTs
    if (lower.find("bearer ") != std::string::npos || lower.find("-----begin ") != std::string::npos ||
        lower.find("$argon2") != std::string::npos || lower.find("$2a$") != std::string::npos ||
        lower.find("$2b$") != std::string::npos || lower.find("$2y$") != std::string::npos ||
        contains_sensitive_assignment(lower) || contains_embedded_jwt(value)) {
        return "[REDACTED]";
    }

    if (value.size() > kMaxMetadataValueLength) {
        return std::string(value.substr(0, kMaxMetadataValueLength));
    }
    return std::string(value);
}

::securecloud::audit::v1::AuditEventProto AuthAuditMapper::map(const domain::AuthOutboxEntity& entity) const {
    return to_proto(entity, default_producer_instance_);
}

::securecloud::audit::v1::AuditEventProto AuthAuditMapper::to_proto(const domain::AuthOutboxEntity& entity,
                                                                    std::string_view default_producer_instance) {
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(entity.payload_json);
    } catch (const std::exception& ex) {
        throw std::runtime_error(std::string("Malformed outbox payload_json: ") + ex.what());
    }

    if (!j.is_object()) {
        throw std::invalid_argument("Outbox payload_json must be a JSON object");
    }

    // 1. Validate event_id (RFC 9562 UUIDv7)
    const std::string event_id = j.value("event_id", entity.event_id.to_string());
    if (!is_valid_uuid_v7(event_id)) {
        throw std::invalid_argument("Audit event_id must be a valid RFC 9562 UUIDv7: " + event_id);
    }

    // 2. Validate occurred_at_ms within clock-skew bounds
    if (!j.contains("occurred_at_ms") || !j["occurred_at_ms"].is_number_integer()) {
        throw std::invalid_argument("Audit event missing integer occurred_at_ms");
    }
    const int64_t occurred_at_ms = j["occurred_at_ms"].get<int64_t>();
    const int64_t now_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    if (occurred_at_ms <= 0 || occurred_at_ms > now_ms + kMaxFutureSkewMs || occurred_at_ms < now_ms - kMaxPastAgeMs) {
        throw std::invalid_argument("Audit occurred_at_ms outside acceptable clock-skew bounds");
    }

    // 3. Validate event_type namespace & max length (64)
    const std::string event_type = j.value("event_type", entity.event_type);
    if (!is_valid_auth_event_type(event_type)) {
        throw std::invalid_argument("Invalid Auth audit event_type namespace or length: " + event_type);
    }

    // 4. Severity & producer identity (max length 64)
    const std::string severity_str = j.value("severity", std::string(domain::to_string(entity.severity)));
    const auto severity_proto = parse_severity(severity_str);

    std::string producer_instance = j.value("producer_instance", std::string{});
    if ((producer_instance.empty() || producer_instance == "auth-1") && !default_producer_instance.empty()) {
        producer_instance = std::string(default_producer_instance);
    }
    if (producer_instance.empty()) {
        producer_instance = "auth";
    }
    if (producer_instance.size() > kMaxInstanceLength) {
        producer_instance.resize(kMaxInstanceLength);
    }

    // 5. Actor & Target extraction and validation (max length 128)
    const auto actor_type = parse_actor_type(j.value("actor_type", std::string{}));
    const std::string actor_id = j.value("actor_id", std::string{});
    if (actor_id.empty() || actor_id.size() > kMaxActorIdLength) {
        throw std::invalid_argument("Audit actor_id must be non-empty and <= 128 chars");
    }

    const auto target_type = parse_target_type(j.value("target_type", std::string{}));
    const std::string target_id = j.value("target_id", std::string{});
    if (target_id.empty() || target_id.size() > kMaxTargetIdLength) {
        throw std::invalid_argument("Audit target_id must be non-empty and <= 128 chars");
    }

    // 6. Correlation & Causation IDs (max length 64)
    std::string correlation_id = j.value("correlation_id", std::string{});
    if (correlation_id.empty()) {
        correlation_id = event_id;
    }
    if (correlation_id.size() > kMaxCorrelationIdLength) {
        throw std::invalid_argument("Audit correlation_id exceeds 64 chars");
    }

    ::securecloud::audit::v1::AuditEventProto proto;
    proto.set_event_id(event_id);
    proto.set_occurred_at_ms(occurred_at_ms);
    proto.set_event_type(event_type);
    proto.set_severity(severity_proto);
    proto.set_producer_service(::securecloud::audit::v1::PRODUCER_SERVICE_AUTH);
    proto.set_producer_instance(producer_instance);
    proto.set_actor_type(actor_type);
    proto.set_actor_id(actor_id);
    proto.set_target_type(target_type);
    proto.set_target_id(target_id);
    proto.set_correlation_id(correlation_id);

    if (j.contains("causation_id") && j["causation_id"].is_string()) {
        const std::string causation_id = j["causation_id"].get<std::string>();
        if (!causation_id.empty()) {
            if (causation_id.size() > kMaxCausationIdLength) {
                throw std::invalid_argument("Audit causation_id exceeds 64 chars");
            }
            proto.set_causation_id(causation_id);
        }
    }

    // 7. Sanitize metadata keys & values (zero-secrets guarantee aligned with SensitiveDataGuard)
    if (j.contains("metadata") && j["metadata"].is_object()) {
        auto* meta_map = proto.mutable_metadata();
        for (const auto& [raw_key, raw_val] : j["metadata"].items()) {
            if (static_cast<std::size_t>(meta_map->size()) >= kMaxMetadataEntries) {
                break;
            }
            // Normalize `credential_identifier` to `account_identifier` so SensitiveDataGuard
            // does not reject the `credential` substring while preserving login identifier traceability.
            const std::string effective_key =
                (raw_key == "credential_identifier") ? std::string("account_identifier") : raw_key;

            if (effective_key.empty() || effective_key.size() > kMaxMetadataKeyLength) {
                continue;
            }
            if (is_sensitive_metadata_key(effective_key)) {
                continue;
            }

            std::string serialized_val;
            if (raw_val.is_string()) {
                serialized_val = raw_val.get<std::string>();
            } else if (raw_val.is_null()) {
                continue;
            } else {
                serialized_val = raw_val.dump();
            }

            (*meta_map)[effective_key] = sanitize_metadata_value(serialized_val);
        }
    }

    return proto;
}

} // namespace securecloud::auth::audit
