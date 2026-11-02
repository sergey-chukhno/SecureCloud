#pragma once

#include "audit_config.hpp"
#include "domain/producer_identity_validator.hpp"
#include "query/audit_query_authorizer.hpp"
#include "query/audit_query_types.hpp"
#include "query/audit_query_validator.hpp"
#include "query/query_bulkhead_limiter.hpp"
#include "repository/audit_event_repository_interface.hpp"

#include <atomic>
#include <chrono>
#include <grpcpp/support/status.h>
#include <memory>
#include <optional>
#include <string_view>

namespace securecloud::audit::query {

struct QueryServiceMetrics {
    std::atomic<uint64_t> queries_executed_total{0};
    std::atomic<uint64_t> queries_denied_total{0};
    std::atomic<uint64_t> queries_failed_total{0};
};

class AuditQueryApplicationService {
  public:
    AuditQueryApplicationService(std::shared_ptr<repository::IAuditEventRepository> repository, QueryConfig config);

    /// Executes a filtered, paginated search query with authorization and bulkhead bounds.
    [[nodiscard]] grpc::Status execute_query(const domain::PeerIdentity& caller, AuditQueryFilter filter,
                                             AuditQueryPageResult& out_result);

    /// Looks up a single audit event by UUIDv7 ID with partition pruning and bulkhead bounds.
    [[nodiscard]] grpc::Status get_event_by_id(const domain::PeerIdentity& caller, std::string_view event_id_str,
                                               std::optional<domain::AuditEvent>& out_event);

    [[nodiscard]] const QueryServiceMetrics& metrics() const noexcept { return metrics_; }
    [[nodiscard]] QueryBulkheadLimiter& bulkhead() noexcept { return bulkhead_; }
    [[nodiscard]] const QueryBulkheadLimiter& bulkhead() const noexcept { return bulkhead_; }

  private:
    std::shared_ptr<repository::IAuditEventRepository> repository_;
    QueryConfig config_;
    QueryBulkheadLimiter bulkhead_;
    QueryServiceMetrics metrics_{};
};

} // namespace securecloud::audit::query