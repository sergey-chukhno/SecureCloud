#include "files/audit/files_audit_mapper.hpp"

#include "files/audit/files_audit_proto_validator.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <nlohmann/json.hpp>
#include <unordered_map>
#include <unordered_set>

namespace securecloud::files::audit {

namespace {

constexpr std::string_view k_redacted_placeholder = "[REDACTED]";

// Forbidden key substrings (case-insensitive)
constexpr std::array<std::string_view, 25> k_forbidden_key_substrings = {"password",
                                                                         "passwd",
                                                                         "secret",
                                                                         "token",
                                                                         "credential",
                                                                         "private_key",
                                                                         "privkey",
                                                                         "encryption_key",
                                                                         "api_key",
                                                                         "ciphertext",
                                                                         "encrypted_data",
                                                                         "plaintext",
                                                                         "encrypted_filename",
                                                                         "encrypted_mime_type",
                                                                         "metadata_nonce",
                                                                         "metadata_tag",
                                                                         "client_encryption_metadata",
                                                                         "capability_token",
                                                                         "s3_secret",
                                                                         "mfa",
                                                                         "totp",
                                                                         "seed",
                                                                         "salt",
                                                                         "filename",
                                                                         "file_name"};

// Envelope keys consumed directly into AuditEventProto fields rather than duplicated into metadata
const std::unordered_set<std::string> k_envelope_only_keys = {
    "severity",    "actor_type", "actor_id",       "owner_user_id", "user_id",     "caller_user_id",
    "target_type", "target_id",  "correlation_id", "request_id",    "causation_id"};

// Rolling-upgrade legacy FILE_* -> canonical E01..E16 `file.*` translation table
const std::unordered_map<std::string, std::string> k_legacy_event_type_map = {
    {"FILE_CREATED", "file.created"},
    {"FILE_VERSION_CREATED", "file.version.created"},
    {"FILE_UPLOADING", "file.upload.initiated"},
    {"FILE_AVAILABLE", "file.upload.completed"},
    {"TRANSFER_CANCELLED", "file.upload.cancelled"},
    {"FILE_FAILED", "file.finalization.failed"},
    {"FILE_EXPIRED", "file.expired"},
    {"FILE_UPLOAD_INITIATED", "file.created"},
    {"FILE_FINALIZING", "file.upload.completed"},
    {"FILE_UPLOAD_COMPLETED", "file.upload.completed"},
    {"FILE_FINALIZED", "file.upload.completed"},
    {"FILE_UPLOAD_FAILED", "file.upload.failed"},
    {"FILE_UPLOAD_ABORTED", "file.upload.failed"},
    {"FILE_CHUNK_UPLOADED", "file.chunk.uploaded"},
    {"FILE_DOWNLOADED", "file.downloaded"},
    {"FILE_DOWNLOAD_COMPLETED", "file.downloaded"},
    {"FILE_DOWNLOAD_DENIED", "file.download.denied"},
    {"FILE_METADATA_UPDATED", "file.metadata.updated"},
    {"FILE_RENAMED", "file.metadata.updated"},
    {"FILE_VERSION_RESTORED", "file.version.restored"},
    {"FILE_SHARED", "file.access.granted"},
    {"FILE_ACCESS_GRANTED", "file.access.granted"},
    {"FILE_UNSHARED", "file.access.revoked"},
    {"FILE_ACCESS_REVOKED", "file.access.revoked"},
    {"FILE_ACCESS_DENIED", "file.access.denied"},
    {"FILE_CAPABILITY_ISSUED", "file.capability.issued"},
    {"CAPABILITY_ISSUED", "file.capability.issued"},
    {"FILE_CAPABILITY_REJECTED", "file.capability.rejected"},
    {"CAPABILITY_REJECTED", "file.capability.rejected"},
    {"FILE_DELETED", "file.deleted"},
    {"FILE_SOFT_DELETED", "file.deleted"},
    {"FILE_PURGED", "file.purged"},
    {"FILE_HARD_DELETED", "file.purged"},
};

[[nodiscard]] std::string to_lower(std::string_view sv) {
    std::string out(sv);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

[[nodiscard]] std::string to_upper(std::string_view sv) {
    std::string out(sv);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return out;
}

[[nodiscard]] std::string normalize_event_type(std::string_view raw_type) {
    if (raw_type.empty()) {
        return {};
    }

    const std::string upper = to_upper(raw_type);
    if (const auto it = k_legacy_event_type_map.find(upper); it != k_legacy_event_type_map.end()) {
        return it->second;
    }

    // Fallback rolling-upgrade rule for unmapped `FILE_*` legacy names
    if (upper.rfind("FILE_", 0) == 0 && upper.size() > 5) {
        return "file." + to_lower(std::string_view(upper).substr(5));
    }

    return to_lower(raw_type);
}

[[nodiscard]] bool is_valid_metadata_key(std::string_view key) noexcept {
    if (key.empty() || key.size() > FilesAuditMapper::k_max_metadata_key_length) {
        return false;
    }
    for (char c : key) {
        const auto uc = static_cast<unsigned char>(c);
        if (!std::isalnum(uc) && c != '_' && c != '.' && c != '-') {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool is_printable_ascii_no_space(std::string_view sv) noexcept {
    for (char c : sv) {
        const auto uc = static_cast<unsigned char>(c);
        if (uc <= 32 || uc >= 127) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool is_forbidden_metadata_key(std::string_view key) {
    const std::string lower = to_lower(key);

    // Exact or suffix/segment match on `key` (e.g., "key", "file_key", "master_key", "s3.key")
    if (lower == "key" || lower.ends_with("_key") || lower.ends_with(".key") || lower.ends_with("-key") ||
        lower.starts_with("key_") || lower.starts_with("key.")) {
        return true;
    }

    for (const auto& term : k_forbidden_key_substrings) {
        if (lower.find(term) != std::string_view::npos) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool is_base64url_char(char c) noexcept {
    const auto uc = static_cast<unsigned char>(c);
    return std::isalnum(uc) || c == '-' || c == '_';
}

[[nodiscard]] bool contains_jwt_pattern(std::string_view value) noexcept {
    std::size_t pos = 0;
    while ((pos = value.find("eyJ", pos)) != std::string_view::npos) {
        std::size_t idx = pos + 3;
        while (idx < value.size() && is_base64url_char(value[idx])) {
            ++idx;
        }
        if (idx < value.size() && value[idx] == '.' && idx > pos + 3) {
            const std::size_t seg2_start = idx + 1;
            idx = seg2_start;
            while (idx < value.size() && is_base64url_char(value[idx])) {
                ++idx;
            }
            if (idx < value.size() && value[idx] == '.' && idx > seg2_start) {
                const std::size_t seg3_start = idx + 1;
                idx = seg3_start;
                while (idx < value.size() && is_base64url_char(value[idx])) {
                    ++idx;
                }
                if (idx > seg3_start) {
                    return true;
                }
            }
        }
        pos += 3;
    }
    return false;
}

[[nodiscard]] bool contains_pem_private_key(std::string_view value) noexcept {
    std::size_t pos = 0;
    while ((pos = value.find("-----BEGIN ", pos)) != std::string_view::npos) {
        const std::size_t end_pos = value.find("PRIVATE KEY-----", pos + 11);
        if (end_pos != std::string_view::npos) {
            return true;
        }
        pos += 11;
    }
    return false;
}

[[nodiscard]] bool contains_bearer_token(std::string_view value) {
    const std::string lower = to_lower(value);
    std::size_t pos = 0;
    while ((pos = lower.find("bearer ", pos)) != std::string_view::npos) {
        if (pos == 0 || !std::isalnum(static_cast<unsigned char>(lower[pos - 1]))) {
            const std::size_t token_start = pos + 7;
            if (token_start < lower.size() && !std::isspace(static_cast<unsigned char>(lower[token_start]))) {
                return true;
            }
        }
        pos += 7;
    }
    return false;
}

[[nodiscard]] bool contains_password_hash(std::string_view value) noexcept {
    // Argon2id / Argon2i / Argon2d
    if (value.find("$argon2id$") != std::string_view::npos || value.find("$argon2i$") != std::string_view::npos ||
        value.find("$argon2d$") != std::string_view::npos) {
        return true;
    }

    // bcrypt ($2a$, $2b$, $2x$, $2y$ followed by 2-digit cost and '$')
    constexpr std::array<std::string_view, 4> k_bcrypt_prefixes = {"$2a$", "$2b$", "$2x$", "$2y$"};
    for (const auto& prefix : k_bcrypt_prefixes) {
        std::size_t pos = 0;
        while ((pos = value.find(prefix, pos)) != std::string_view::npos) {
            if (pos + 7 <= value.size() && std::isdigit(static_cast<unsigned char>(value[pos + 4])) &&
                std::isdigit(static_cast<unsigned char>(value[pos + 5])) && value[pos + 6] == '$') {
                return true;
            }
            pos += prefix.size();
        }
    }
    return false;
}

[[nodiscard]] std::string scrub_metadata_value(std::string_view raw) {
    if (contains_pem_private_key(raw) || contains_jwt_pattern(raw) || contains_bearer_token(raw) ||
        contains_password_hash(raw)) {
        return std::string(k_redacted_placeholder);
    }

    std::string out(raw);
    if (out.size() > FilesAuditMapper::k_max_metadata_value_length) {
        out.resize(FilesAuditMapper::k_max_metadata_value_length);
    }
    return out;
}

[[nodiscard]] securecloud::audit::v1::SeverityProto map_outbox_severity(OutboxSeverity sev) noexcept {
    switch (sev) {
    case OutboxSeverity::Info:
        return securecloud::audit::v1::SEVERITY_INFO;
    case OutboxSeverity::Warning:
        return securecloud::audit::v1::SEVERITY_WARNING;
    case OutboxSeverity::Security:
        return securecloud::audit::v1::SEVERITY_SECURITY;
    case OutboxSeverity::Critical:
        return securecloud::audit::v1::SEVERITY_CRITICAL;
    }
    return securecloud::audit::v1::SEVERITY_INFO;
}

[[nodiscard]] securecloud::audit::v1::SeverityProto parse_severity_string(std::string_view raw) {
    const std::string upper = to_upper(raw);
    if (upper == "CRITICAL") {
        return securecloud::audit::v1::SEVERITY_CRITICAL;
    }
    if (upper == "SECURITY") {
        return securecloud::audit::v1::SEVERITY_SECURITY;
    }
    if (upper == "WARNING") {
        return securecloud::audit::v1::SEVERITY_WARNING;
    }
    return securecloud::audit::v1::SEVERITY_INFO;
}

[[nodiscard]] bool is_security_event_type(std::string_view canonical_type) noexcept {
    return canonical_type == "file.access.revoked" || canonical_type == "file.access.denied" ||
           canonical_type == "file.download.denied" || canonical_type == "file.capability.rejected" ||
           canonical_type == "file.chunk.integrity_failed";
}

[[nodiscard]] securecloud::audit::v1::ActorTypeProto parse_actor_type_string(std::string_view raw) {
    const std::string upper = to_upper(raw);
    if (upper == "USER") {
        return securecloud::audit::v1::ACTOR_TYPE_USER;
    }
    if (upper == "DEVICE") {
        return securecloud::audit::v1::ACTOR_TYPE_DEVICE;
    }
    if (upper == "SERVICE") {
        return securecloud::audit::v1::ACTOR_TYPE_SERVICE;
    }
    if (upper == "SYSTEM") {
        return securecloud::audit::v1::ACTOR_TYPE_SYSTEM;
    }
    return securecloud::audit::v1::ACTOR_TYPE_UNSPECIFIED;
}

void insert_sanitized_entry(google::protobuf::Map<std::string, std::string>* meta_map, std::string_view key,
                            const nlohmann::json& val) {
    if (!meta_map || static_cast<std::size_t>(meta_map->size()) >= FilesAuditMapper::k_max_metadata_entries) {
        return;
    }
    if (!is_valid_metadata_key(key) || is_forbidden_metadata_key(key)) {
        return;
    }

    if (val.is_string()) {
        (*meta_map)[std::string(key)] = scrub_metadata_value(val.get_ref<const std::string&>());
    } else if (val.is_number()) {
        (*meta_map)[std::string(key)] = scrub_metadata_value(val.dump());
    } else if (val.is_boolean()) {
        (*meta_map)[std::string(key)] = val.get<bool>() ? "true" : "false";
    }
}

} // namespace

securecloud::audit::v1::AuditEventProto FilesAuditMapper::to_proto(const FilesOutboxEntity& entity,
                                                                   std::string_view producer_instance) {
    securecloud::audit::v1::AuditEventProto proto;
    proto.set_event_id(entity.event_id);

    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(entity.created_at.time_since_epoch()).count();
    proto.set_occurred_at_ms(ms);

    const std::string canonical_event_type = normalize_event_type(entity.event_type);
    proto.set_event_type(canonical_event_type);

    // Producer identity
    proto.set_producer_service(securecloud::audit::v1::PRODUCER_SERVICE_FILES);
    const std::string_view effective_instance =
        producer_instance.empty() ? k_default_producer_instance : producer_instance;
    proto.set_producer_instance(std::string(effective_instance.substr(0, k_max_id_length)));

    // Target mapping (`aggregate_id == nullopt` -> TARGET_TYPE_SERVICE)
    if (entity.aggregate_type == "SERVICE") {
        proto.set_target_type(securecloud::audit::v1::TARGET_TYPE_SERVICE);
        proto.set_target_id((entity.aggregate_id.has_value() && !entity.aggregate_id->empty()) ? *entity.aggregate_id
                                                                                               : "files");
    } else if (entity.aggregate_id.has_value() && !entity.aggregate_id->empty()) {
        proto.set_target_type(securecloud::audit::v1::TARGET_TYPE_FILE);
        proto.set_target_id(*entity.aggregate_id);
    } else {
        proto.set_target_type(securecloud::audit::v1::TARGET_TYPE_SERVICE);
        proto.set_target_id("files");
    }

    // Severity mapping from entity + canonical security event promotion
    auto severity = map_outbox_severity(entity.severity);
    if ((severity == securecloud::audit::v1::SEVERITY_INFO || severity == securecloud::audit::v1::SEVERITY_WARNING) &&
        is_security_event_type(canonical_event_type)) {
        severity = securecloud::audit::v1::SEVERITY_SECURITY;
    }
    proto.set_severity(severity);

    // Default correlation_id to event_id unless overridden by valid correlation_id/request_id in payload
    proto.set_correlation_id(entity.event_id);

    auto explicit_actor_type = securecloud::audit::v1::ACTOR_TYPE_UNSPECIFIED;

    if (!entity.payload_json.empty()) {
        const auto payload = nlohmann::json::parse(entity.payload_json, nullptr, /*allow_exceptions=*/false);
        if (payload.is_object()) {
            // Promote severity if explicitly set in JSON payload
            if (payload.contains("severity") && payload["severity"].is_string() &&
                proto.severity() == securecloud::audit::v1::SEVERITY_INFO) {
                const auto json_sev = parse_severity_string(payload["severity"].get_ref<const std::string&>());
                if (json_sev != securecloud::audit::v1::SEVERITY_INFO) {
                    proto.set_severity(json_sev);
                }
            }

            // Extract actor_type & actor_id
            if (payload.contains("actor_type") && payload["actor_type"].is_string()) {
                explicit_actor_type = parse_actor_type_string(payload["actor_type"].get_ref<const std::string&>());
            }

            for (const char* actor_key : {"actor_id", "owner_user_id", "user_id", "caller_user_id"}) {
                if (payload.contains(actor_key) && payload[actor_key].is_string()) {
                    const auto& candidate = payload[actor_key].get_ref<const std::string&>();
                    if (!candidate.empty()) {
                        proto.set_actor_id(candidate);
                        break;
                    }
                }
            }

            // Extract correlation_id (preferring correlation_id, then request_id)
            for (const char* corr_key : {"correlation_id", "request_id"}) {
                if (payload.contains(corr_key) && payload[corr_key].is_string()) {
                    const auto& candidate = payload[corr_key].get_ref<const std::string&>();
                    if (!candidate.empty() && candidate.size() <= k_max_id_length &&
                        is_printable_ascii_no_space(candidate)) {
                        proto.set_correlation_id(candidate);
                        break;
                    }
                }
            }

            // Extract optional causation_id
            if (payload.contains("causation_id") && payload["causation_id"].is_string()) {
                const auto& causation = payload["causation_id"].get_ref<const std::string&>();
                if (!causation.empty() && causation.size() <= k_max_id_length &&
                    is_printable_ascii_no_space(causation)) {
                    proto.set_causation_id(causation);
                }
            }

            // Stage-2 metadata sanitization
            auto* meta_map = proto.mutable_metadata();
            for (const auto& [key, val] : payload.items()) {
                if (static_cast<std::size_t>(meta_map->size()) >= k_max_metadata_entries) {
                    break;
                }
                if (k_envelope_only_keys.contains(key)) {
                    continue;
                }
                if (is_forbidden_metadata_key(key)) {
                    continue;
                }

                if (val.is_object()) {
                    // Flatten safe scalar children one level deep (`parent.child`); drop deeper nested objects/arrays
                    if (is_valid_metadata_key(key)) {
                        for (const auto& [sub_key, sub_val] : val.items()) {
                            if (static_cast<std::size_t>(meta_map->size()) >= k_max_metadata_entries) {
                                break;
                            }
                            if (is_forbidden_metadata_key(sub_key)) {
                                continue;
                            }
                            if (sub_val.is_primitive() && !sub_val.is_null()) {
                                const std::string flattened_key = key + "." + sub_key;
                                insert_sanitized_entry(meta_map, flattened_key, sub_val);
                            }
                        }
                    }
                } else if (val.is_primitive() && !val.is_null()) {
                    insert_sanitized_entry(meta_map, key, val);
                }
                // Arrays and nulls are dropped
            }
        }
    }

    // Finalize actor_type / actor_id invariants
    if (proto.actor_id().empty()) {
        proto.set_actor_id("system");
        proto.set_actor_type(securecloud::audit::v1::ACTOR_TYPE_SYSTEM);
    } else if (explicit_actor_type != securecloud::audit::v1::ACTOR_TYPE_UNSPECIFIED) {
        proto.set_actor_type(explicit_actor_type);
    } else if (proto.actor_id() == "system") {
        proto.set_actor_type(securecloud::audit::v1::ACTOR_TYPE_SYSTEM);
    } else if (proto.actor_id() == "gateway" || proto.actor_id() == "files" || proto.actor_id() == "auth" ||
               proto.actor_id() == "messaging" || proto.actor_id() == "audit") {
        proto.set_actor_type(securecloud::audit::v1::ACTOR_TYPE_SERVICE);
    } else {
        proto.set_actor_type(securecloud::audit::v1::ACTOR_TYPE_USER);
    }

    return proto;
}

MappedAuditEvent FilesAuditMapper::to_validated_proto(const FilesOutboxEntity& entity,
                                                      std::chrono::system_clock::time_point now,
                                                      std::string_view producer_instance) {
    static const FilesAuditProtoValidator validator;

    MappedAuditEvent mapped;
    mapped.proto = to_proto(entity, producer_instance);

    const auto validation = validator.validate(mapped.proto, now);
    mapped.valid = validation.valid;
    if (!validation.valid) {
        mapped.validation_error = validation.joined_errors();
    }
    return mapped;
}

} // namespace securecloud::files::audit
