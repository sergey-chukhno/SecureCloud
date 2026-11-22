#include "files/service/files_audit_event_publisher.hpp"

#include "files/domain/metadata_validator.hpp"

#include <chrono>
#include <iostream>
#include <unordered_set>

namespace securecloud::files::service {

FilesAuditEventPublisher::FilesAuditEventPublisher(std::shared_ptr<FilesOutboxRepository> outbox_repo)
    : outbox_repo_(std::move(outbox_repo)) {}

void FilesAuditEventPublisher::publish_in_tx(const FilesAuditRecord& record, pqxx::work& tx) {
    if (!outbox_repo_)
        return;

    FilesOutboxEntity entity{.event_id = generate_uuid_v7(),
                             .aggregate_id = record.target_id,
                             .event_type = record.event_type,
                             .severity = OutboxSeverity::Info,
                             .payload_json = format_payload(record),
                             .status = OutboxStatus::Pending,
                             .retry_count = 0,
                             .created_at = std::chrono::system_clock::now()};

    outbox_repo_->stage_event(entity, tx);
}

void FilesAuditEventPublisher::publish_autonomous(const FilesAuditRecord& record) noexcept {
    if (!outbox_repo_)
        return;

    try {
        FilesOutboxEntity entity{.event_id = generate_uuid_v7(),
                                 .aggregate_id = record.target_id,
                                 .event_type = record.event_type,
                                 .payload_json = format_payload(record),
                                 .status = OutboxStatus::Pending,
                                 .created_at = std::chrono::system_clock::now()};
        outbox_repo_->stage_event(entity);
    } catch (const std::exception& ex) {
        // Stage-1 constraint: autonomous audit failure must NOT break the application flow.
        std::cerr << "[FilesAuditEventPublisher] Failed to record autonomous audit event '" << record.event_type
                  << "': " << ex.what() << "\n";
    }
}

void FilesAuditEventPublisher::sanitize_metadata(std::map<std::string, std::string>& meta) const {
    static const std::unordered_set<std::string> blocked_keys = {"encryption_key", "secret",   "token", "password",
                                                                 "ciphertext",     "filename", "key"};

    for (auto it = meta.begin(); it != meta.end();) {
        if (blocked_keys.find(it->first) != blocked_keys.end()) {
            it = meta.erase(it);
        } else {
            ++it;
        }
    }
}

std::string FilesAuditEventPublisher::format_payload(const FilesAuditRecord& record) const {
    nlohmann::json payload;
    payload["severity"] = record.severity.empty() ? "INFO" : record.severity;
    payload["actor_type"] = record.actor_type.empty() ? "USER" : record.actor_type;
    payload["actor_id"] = record.actor_id;
    payload["target_type"] = record.target_type;
    payload["target_id"] = record.target_id;
    payload["correlation_id"] = record.correlation_id;

    auto safe_meta = record.metadata;
    sanitize_metadata(safe_meta);

    for (const auto& [k, v] : safe_meta) {
        payload[k] = v;
    }

    return payload.dump();
}

} // namespace securecloud::files::service
