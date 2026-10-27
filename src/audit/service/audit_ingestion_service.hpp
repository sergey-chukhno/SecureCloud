#pragma once

#include "domain/audit_event.hpp"
#include "repository/audit_event_repository_interface.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace securecloud::audit::service {

    struct IngestionResult {
        bool success{false};
        std::string error_code{};
        std::string error_message{};
        std::chrono::system_clock::time_point received_at{};
    };

    struct BatchIngestionResult {
        uint32_t accepted_count{0};
        uint32_t rejected_count{0};
        std::vector<std::pair<domain::EventId, IngestionResult>> item_results{};
    };

    class AuditIngestionService {
    public:
        explicit AuditIngestionService(std::shared_ptr<repository::IAuditEventRepository> repository);

        [[nodiscard]] IngestionResult ingest_single(const domain::AuditEvent& event);

        [[nodiscard]] BatchIngestionResult ingest_batch(const std::vector<domain::AuditEvent>& events);

    private:
        std::shared_ptr<repository::IAuditEventRepository> repository_;
    };

} // namespace securecloud::audit::service