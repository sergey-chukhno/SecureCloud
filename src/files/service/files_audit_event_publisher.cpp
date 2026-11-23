#include "files/service/files_audit_event_publisher.hpp"

#include "files/audit/files_outbox_diagnostics.hpp"
#include "files/audit/files_outbox_metrics.hpp"
#include "files/domain/metadata_validator.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <string_view>
#include <unordered_set>

namespace securecloud::files::service {

namespace {

constexpr size_t k_max_metadata_entries = 32;
constexpr size_t k_max_metadata_key_length = 64;
constexpr size_t k_max_metadata_value_length = 1024;
constexpr std::string_view k_redacted_placeholder = "[REDACTED]";

constexpr std::array<std::string_view, 30> k_forbidden_key_substrings = {"password",
                                                                         "passwd",
                                                                         "secret",
                                                                         "token",
                                                                         "credential",
                                                                         "private_key",
                                                                         "privkey",
                                                                         "encryption_key",
                                                                         "api_key",
                                                                         "signing_key",
                                                                         "ciphertext",
                                                                         "encrypted_data",
                                                                         "chunk_data",
                                                                         "plaintext",
                                                                         "encrypted_filename",
                                                                         "encrypted_mime_type",
                                                                         "metadata_nonce",
                                                                         "metadata_tag",
                                                                         "client_encryption_metadata",
                                                                         "capability_token",
                                                                         "s3_secret",
                                                                         "s3_access",
                                                                         "db_password",
                                                                         "authorization",
                                                                         "mfa",
                                                                         "totp",
                                                                         "seed",
                                                                         "salt",
                                                                         "filename",
                                                                         "file_name"};

const std::unordered_set<std::string> k_envelope_keys = {"severity",    "actor_type", "actor_id",
                                                         "target_type", "target_id",  "correlation_id"};

[[nodiscard]] std::string to_lower_copy(std::string_view sv) {
    std::string out(sv);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

[[nodiscard]] std::string to_upper_copy(std::string_view sv) {
    std::string out(sv);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return out;
}

[[nodiscard]] OutboxSeverity parse_outbox_severity(std::string_view raw) {
    const std::string upper = to_upper_copy(raw);
    if (upper == "CRITICAL") {
        return OutboxSeverity::Critical;
    }
    if (upper == "SECURITY") {
        return OutboxSeverity::Security;
    }
    if (upper == "WARNING") {
        return OutboxSeverity::Warning;
    }
    return OutboxSeverity::Info;
}

[[nodiscard]] bool is_valid_metadata_key(std::string_view key) noexcept {
    if (key.empty() || key.size() > k_max_metadata_key_length) {
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

[[nodiscard]] bool is_forbidden_metadata_key(std::string_view key) {
    const std::string lower = to_lower_copy(key);
    if (k_envelope_keys.contains(lower)) {
        return true;
    }
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
        if (value.find("PRIVATE KEY-----", pos + 11) != std::string_view::npos) {
            return true;
        }
        pos += 11;
    }
    return false;
}

[[nodiscard]] bool contains_bearer_token(std::string_view value) {
    const std::string lower = to_lower_copy(value);
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
    if (value.find("$argon2id$") != std::string_view::npos || value.find("$argon2i$") != std::string_view::npos ||
        value.find("$argon2d$") != std::string_view::npos) {
        return true;
    }
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
    if (out.size() > k_max_metadata_value_length) {
        out.resize(k_max_metadata_value_length);
    }
    return out;
}

FilesOutboxEntity build_outbox_entity(const FilesAuditRecord& record, std::string payload_json) {
    FilesOutboxEntity entity;
    entity.event_id = generate_uuid_v7();
    entity.aggregate_type = record.target_type.empty() ? "FILE" : record.target_type;
    if (entity.aggregate_type != "SERVICE" && is_valid_uuid(record.target_id)) {
        entity.aggregate_id = record.target_id;
    } else {
        entity.aggregate_id = std::nullopt;
    }
    entity.event_type = record.event_type;
    entity.severity = parse_outbox_severity(record.severity);
    entity.payload_json = std::move(payload_json);
    entity.status = OutboxStatus::Pending;
    entity.retry_count = 0;
    entity.created_at = std::chrono::system_clock::now();
    entity.processed_at = std::nullopt;
    entity.last_error = std::nullopt;
    entity.leased_until = std::nullopt;
    return entity;
}

} // namespace

FilesAuditEventPublisher::FilesAuditEventPublisher(std::shared_ptr<FilesOutboxRepository> outbox_repo)
    : outbox_repo_(std::move(outbox_repo)) {}

void FilesAuditEventPublisher::set_notify_callback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    notify_callback_ = std::move(callback);
}

void FilesAuditEventPublisher::notify_relay() noexcept {
    try {
        std::function<void()> cb;
        {
            std::lock_guard<std::mutex> lock(callback_mutex_);
            cb = notify_callback_;
        }
        if (cb) {
            cb();
        }
    } catch (...) {
        // Relay wakeup notification is best-effort and must never escape noexcept callers.
    }
}

void FilesAuditEventPublisher::publish_in_tx(const FilesAuditRecord& record, pqxx::work& tx) {
    if (!outbox_repo_) {
        return;
    }

    auto entity = build_outbox_entity(record, format_payload(record));
    outbox_repo_->stage_event(entity, tx);
    securecloud::files::audit::FilesOutboxMetrics::instance().record_staged(
        securecloud::files::audit::FilesOutboxCategory::Transactional);
}

void FilesAuditEventPublisher::publish_autonomous(const FilesAuditRecord& record) noexcept {
    if (!outbox_repo_) {
        return;
    }

    try {
        auto entity = build_outbox_entity(record, format_payload(record));
        outbox_repo_->stage_event(entity);
        securecloud::files::audit::FilesOutboxMetrics::instance().record_staged(
            securecloud::files::audit::FilesOutboxCategory::Autonomous);
        notify_relay();
    } catch (const std::exception& ex) {
        // Stage-1 constraint: autonomous audit failure must NOT break the application flow.
        securecloud::files::audit::FilesOutboxDiagnostics::instance().log_event(
            securecloud::files::audit::FilesDiagnosticCategory::Batch, "autonomous_stage_failed", {}, ex.what());
    } catch (...) {
        securecloud::files::audit::FilesOutboxDiagnostics::instance().log_event(
            securecloud::files::audit::FilesDiagnosticCategory::Batch, "autonomous_stage_failed", {},
            "unknown_exception");
    }
}

void FilesAuditEventPublisher::sanitize_metadata(std::map<std::string, std::string>& meta) const {
    size_t kept = 0;
    for (auto it = meta.begin(); it != meta.end();) {
        if (kept >= k_max_metadata_entries || !is_valid_metadata_key(it->first) ||
            is_forbidden_metadata_key(it->first)) {
            it = meta.erase(it);
        } else {
            it->second = scrub_metadata_value(it->second);
            ++kept;
            ++it;
        }
    }
}

std::string FilesAuditEventPublisher::format_payload(const FilesAuditRecord& record) const {
    nlohmann::json payload;
    payload["severity"] = record.severity.empty() ? "INFO" : to_upper_copy(record.severity);
    payload["actor_type"] = record.actor_type.empty() ? "USER" : to_upper_copy(record.actor_type);
    payload["actor_id"] = record.actor_id.empty() ? "system" : record.actor_id;
    payload["target_type"] = record.target_type.empty() ? "FILE" : record.target_type;
    payload["target_id"] = record.target_id.empty() ? "files" : record.target_id;
    payload["correlation_id"] = record.correlation_id.empty() ? generate_uuid_v7() : record.correlation_id;

    auto safe_meta = record.metadata;
    sanitize_metadata(safe_meta);

    for (const auto& [k, v] : safe_meta) {
        payload[k] = v;
    }

    return payload.dump();
}

} // namespace securecloud::files::service
