#pragma once

#include <chrono>
#include <cstddef>

namespace securecloud::auth::audit {

struct AuthOutboxRelayConfig {
    std::chrono::milliseconds poll_interval{500};
    size_t batch_size{50};                   // Max 100 per AUDIT-004
    std::chrono::seconds lease_duration{30}; // Row lease duration
    std::chrono::milliseconds initial_backoff{250};
    std::chrono::milliseconds max_backoff{30000};
    double backoff_multiplier{2.0};
    double jitter_ratio{0.25};                      // ±25% jitter
    std::chrono::hours published_retention{24 * 7}; // 7 days retention
    size_t purge_batch_size{1000};
    std::chrono::milliseconds purge_interval{std::chrono::hours(1)};
    std::chrono::milliseconds shutdown_drain_timeout{1500};
};

} // namespace securecloud::auth::audit
