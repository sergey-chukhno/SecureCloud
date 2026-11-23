#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace securecloud::gateway::audit {

/**
 * @brief Configuration settings for Gateway WAL audit file spooling.
 */
struct GatewayAuditSpoolConfig {
    std::string spool_directory{"/var/spool/securecloud/gateway/audit"};
    size_t max_spool_bytes{1073741824}; // 1 GiB cap
    size_t max_spool_records{100000};
    uint32_t group_commit_interval_ms{20}; // 20 ms max latency
    uint32_t group_commit_record_threshold{256};
};

} // namespace securecloud::gateway::audit
