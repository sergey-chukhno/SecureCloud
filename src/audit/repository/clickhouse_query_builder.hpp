#pragma once

#include "domain/event_id.hpp"
#include "query/audit_page_cursor.hpp"
#include "query/audit_query_types.hpp"

#include <map>
#include <optional>
#include <string>

namespace securecloud::audit::repository {

    /// Represents a parameterized ClickHouse HTTP query.
    /// Query parameters are passed natively via `param_<name>=<value>` to ensure zero SQL injection risk.
    struct ParameterizedClickHouseQuery {
        std::string sql_template;
        std::map<std::string, std::string> bind_params;
    };

    class ClickHouseQueryBuilder {
    public:
        /// Builds a parameterized SELECT query for filtered event searches with keyset pagination.
        [[nodiscard]] static ParameterizedClickHouseQuery build_filter_query(
            const query::AuditQueryFilter& filter,
            const std::optional<query::AuditPageCursor>& cursor = std::nullopt);

        /// Builds a parameterized SELECT query for single event lookups using UUIDv7 timestamp partition pruning (+/- 10 minutes).
        [[nodiscard]] static ParameterizedClickHouseQuery build_get_by_id_query(const domain::EventId& event_id);
    };

} // namespace securecloud::audit::repository