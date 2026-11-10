#pragma once

#include "gateway_audit_observation.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <list>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace securecloud::gateway::audit {

using FlushCallback = std::function<void(GatewayAuditObservation observation, uint32_t count)>;

/**
 * @brief Sliding time window for aggregating high-frequency observations (E5 Rate Limit, E6 Resource Limit).
 */
class AuditAggregationWindow {
  public:
    AuditAggregationWindow(uint32_t window_sec, size_t max_keys, FlushCallback flush_cb);
    ~AuditAggregationWindow();

    AuditAggregationWindow(const AuditAggregationWindow&) = delete;
    AuditAggregationWindow& operator=(const AuditAggregationWindow&) = delete;

    /// Non-blocking observation entry; flushes via LRU if max_keys capacity is exceeded.
    void add(GatewayAuditObservation observation) noexcept;

    /// Flushes all active aggregated entries immediately.
    void flush_all() noexcept;

  private:
    void background_flush_loop();

    struct WindowEntry {
        GatewayAuditObservation observation;
        uint32_t count{1};
        std::chrono::steady_clock::time_point window_start;
        std::list<std::string>::iterator lru_iter;
    };

    uint32_t window_sec_;
    size_t max_keys_;
    FlushCallback flush_cb_;

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::list<std::string> lru_list_;
    std::unordered_map<std::string, WindowEntry> map_;

    std::atomic<bool> running_{true};
    std::thread flush_thread_;
};

} // namespace securecloud::gateway::audit
