#pragma once

#include "domain/audit_event.hpp"
#include "domain/event_id.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace securecloud::audit::repository {

enum class RepositoryWriteStatus : uint8_t {
    Committed = 0,            // ClickHouse returned HTTP 200 OK
    DeterministicFailure = 1, // Connection refused, auth error, syntax/4xx/5xx before commit
    AmbiguousOutcome = 2      // Socket timeout or connection reset after sending HTTP POST body
};

struct RepositoryBatchWriteResult {
    RepositoryWriteStatus status{RepositoryWriteStatus::DeterministicFailure};
    std::string error_code;
    std::string sanitized_reason;
};

/// Abstract interface for authoritative audit event persistence operations.
class IAuditEventRepository {
  public:
    virtual ~IAuditEventRepository() = default;

    /// Bulk inserts a batch of audit events.
    [[nodiscard]] virtual bool insert_batch(const std::vector<domain::AuditEvent>& events) = 0;

    /// Bulk inserts a batch of audit events with detailed status classification.
    [[nodiscard]] virtual RepositoryBatchWriteResult
    insert_batch_classified(const std::vector<domain::AuditEvent>& events) {
        bool ok = insert_batch(events);
        if (ok) {
            return RepositoryBatchWriteResult{
                .status = RepositoryWriteStatus::Committed,
                .error_code = "",
                .sanitized_reason = ""
            };
        }
        return RepositoryBatchWriteResult{
            .status = RepositoryWriteStatus::DeterministicFailure,
            .error_code = "PERSISTENCE_FAILED",
            .sanitized_reason = "ClickHouse batch insertion failed"
        };
    }

    /// Queries audit events occurring within a specified time range (UTC).
    [[nodiscard]] virtual std::vector<domain::AuditEvent>
    query_by_time_range(std::chrono::system_clock::time_point start, std::chrono::system_clock::time_point end,
                        uint32_t limit) = 0;

    /// Queries audit events produced by a specific service within a time range.
    [[nodiscard]] virtual std::vector<domain::AuditEvent> query_by_producer(const std::string& producer_service,
                                                                            std::chrono::system_clock::time_point start,
                                                                            std::chrono::system_clock::time_point end,
                                                                            uint32_t limit) = 0;

    /// Queries audit events matching a specific correlation ID.
    [[nodiscard]] virtual std::vector<domain::AuditEvent> query_by_correlation_id(const std::string& correlation_id,
                                                                                  uint32_t limit) = 0;

    /// Finds a single audit event by its unique EventId.
    [[nodiscard]] virtual std::optional<domain::AuditEvent> find_by_event_id(const domain::EventId& event_id) = 0;
};

} // namespace securecloud::audit::repository