#pragma once

#include "repository/clickhouse_client.hpp"
#include "securecloud/health/health_status_manager.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

namespace securecloud::audit::health {

struct AuditHealthEvaluatorConfig {
    std::chrono::milliseconds check_interval{1000};
    std::chrono::milliseconds probe_timeout{500};
    uint32_t consecutive_failures_threshold{3};
    uint32_t queue_high_water_pct{90};
    bool auto_start{true};
};

class AuditHealthEvaluator {
  public:
    using ClickHouseProbeFn = std::function<bool(std::chrono::milliseconds)>;
    using QueueHealthFn = std::function<bool(uint32_t& out_occupancy_pct)>;

    AuditHealthEvaluator(common::health::HealthStatusManager& health_manager,
                         std::shared_ptr<repository::ClickHouseClient> clickhouse_client,
                         QueueHealthFn queue_health_fn,
                         AuditHealthEvaluatorConfig config = {});

    AuditHealthEvaluator(common::health::HealthStatusManager& health_manager,
                         ClickHouseProbeFn clickhouse_probe,
                         QueueHealthFn queue_health_fn,
                         AuditHealthEvaluatorConfig config = {});

    ~AuditHealthEvaluator();

    AuditHealthEvaluator(const AuditHealthEvaluator&) = delete;
    AuditHealthEvaluator& operator=(const AuditHealthEvaluator&) = delete;
    AuditHealthEvaluator(AuditHealthEvaluator&&) = delete;
    AuditHealthEvaluator& operator=(AuditHealthEvaluator&&) = delete;

    /// Runs a single synchronous health evaluation iteration. Does not throw exceptions.
    bool evaluate_once() noexcept;

    /// Starts the background periodic monitoring thread.
    void start();

    /// Stops the background periodic monitoring thread.
    void stop() noexcept;

    [[nodiscard]] bool is_clickhouse_healthy() const noexcept;
    [[nodiscard]] bool is_queue_healthy() const noexcept;
    [[nodiscard]] bool is_ready() const noexcept;
    [[nodiscard]] bool is_running() const noexcept;

  private:
    common::health::HealthStatusManager& health_manager_;
    ClickHouseProbeFn clickhouse_probe_;
    QueueHealthFn queue_health_fn_;
    AuditHealthEvaluatorConfig config_;

    std::atomic<bool> is_running_{false};
    std::atomic<bool> is_clickhouse_healthy_{true};
    std::atomic<bool> is_queue_healthy_{true};
    std::atomic<bool> is_ready_{false};
    std::atomic<uint32_t> consecutive_failures_{0};

    std::thread worker_thread_;
    std::mutex cv_mutex_;
    std::condition_variable cv_;
};

} // namespace securecloud::audit::health
