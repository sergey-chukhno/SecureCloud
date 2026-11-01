#pragma once

#include "audit_repository_exceptions.hpp"

#include <string_view>

namespace securecloud::audit::repository {

/// Deterministic application-layer SQL guard that enforces append-only semantics.
class AppendOnlySqlGuard {
  public:
    /// Validates read queries (must begin with SELECT, no semicolons, no forbidden DDL/DML keywords).
    /// @throws AppendOnlyViolationException immediately if a violation is detected.
    static void validate_query_sql(std::string_view sql);

    /// Validates insert queries (must begin with INSERT INTO, target audit_events, no semicolons, no mutation
    /// keywords).
    /// @throws AppendOnlyViolationException immediately if a violation is detected.
    static void validate_insert_sql(std::string_view sql);
};

} // namespace securecloud::audit::repository