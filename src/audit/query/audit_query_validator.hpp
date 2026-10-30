#pragma once

#include "audit_config.hpp"
#include "query/audit_page_cursor.hpp"
#include "query/audit_query_types.hpp"

#include <chrono>
#include <grpcpp/support/status.h>

namespace securecloud::audit::query {

enum class QueryValidationError {
    None = 0,
    MissingTimeRangeBound,
    InvalidTimeRangeOrder,
    TimeWindowExceeded,
    PageSizeExceeded,
    InvalidEventType,
    TooManyEventTypes,
    InvalidActorTargetRequirement,
    InvalidCharacterInIdentifier,
    InvalidCorrelationId,
    InvalidPageToken
};

class AuditQueryValidator {
  public:
    /// Validates and normalizes an AuditQueryFilter against the provided QueryConfig.
    /// Mutates `filter` to populate default time window and effective page size if missing/zero.
    [[nodiscard]] static grpc::Status
    validate_and_normalize(AuditQueryFilter& filter, const QueryConfig& config,
                           std::chrono::system_clock::time_point now = std::chrono::system_clock::now());

  private:
    [[nodiscard]] static bool is_valid_event_type(std::string_view event_type);
    [[nodiscard]] static bool is_safe_identifier(std::string_view id, size_t max_len);
    [[nodiscard]] static bool is_valid_correlation_id(std::string_view token);
};

} // namespace securecloud::audit::query