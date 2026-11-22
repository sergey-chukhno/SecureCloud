#pragma once

#include "files/repository/files_outbox_repository.hpp"

#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>
#include <string>

namespace securecloud::files::service {

struct FilesAuditRecord {
    std::string event_type; // e.g., "file.created", "file.access.denied"
    std::string severity;   // "INFO", "WARNING", "SECURITY"
    std::string actor_type; // "USER", "SYSTEM"
    std::string actor_id;
    std::string target_type; // "FILE", "SERVICE"
    std::string target_id;
    std::string correlation_id;
    std::map<std::string, std::string> metadata;
};

/**
 * @brief Handles Stage-1 sanitization and persistence of canonical E01-E16 events.
 * Supports strict transactional outbox staging and autonomous DB insertion.
 */
class FilesAuditEventPublisher {
  public:
    explicit FilesAuditEventPublisher(std::shared_ptr<FilesOutboxRepository> outbox_repo);

    /**
     * @brief Category A: Publishes event atomically within an existing transaction.
     */
    void publish_in_tx(const FilesAuditRecord& record, pqxx::work& tx);

    /**
     * @brief Category B: Publishes event autonomously. Catches DB exceptions without failing business logic.
     */
    void publish_autonomous(const FilesAuditRecord& record) noexcept;

  private:
    std::string format_payload(const FilesAuditRecord& record) const;
    void sanitize_metadata(std::map<std::string, std::string>& meta) const;

    std::shared_ptr<FilesOutboxRepository> outbox_repo_;
};

} // namespace securecloud::files::service
