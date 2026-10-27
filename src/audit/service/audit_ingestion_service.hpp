#pragma once

#include "domain/audit_event.hpp"
#include "domain/audit_event_validator.hpp"
#include "repository/audit_event_repository_interface.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace securecloud::audit::service {

    struct IngestionResult {
        bool success{false};
        std::string error_code;
        std::string error_message;
        std::chrono::system_clock::time_point received_at;
    };

    struct BatchIngestionResult {
        uint32_t accepted_count{0};
        uint32_t rejected_count{0};
        std::vector<std::pair<domain::EventId, IngestionResult>> item_results;
    };

    class AuditIngestionService {
    public:
        explicit AuditIngestionService(std::shared_ptr<repository::IAuditEventRepository> repository);

        /// Ingests a single audit event, applying domain validation and assigning received_at timestamp.
        [[nodiscard]] IngestionResult ingest_single(domain::AuditEvent event);

        /// Ingests a batch of audit events (enforces max 100 items per batch).
        [[nodiscard]] BatchIngestionResult ingest_batch(std::vector<domain::AuditEvent> events);

        static constexpr size_t kMaxBatchSize = 100;

    private:
        std::shared_ptr<repository::IAuditEventRepository> repository_;
    };

} // namespace securecloud::audit::service