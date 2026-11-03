#include "health/audit_health_evaluator.hpp"

#include <exception>
#include <utility>

namespace securecloud::audit::health {

AuditHealthEvaluator::AuditHealthEvaluator(common::health::HealthStatusManager& health_manager,
                                             std::shared_ptr<repository::ClickHouseClient> clickhouse_client,
                                             QueueHealthFn queue_health_fn,
                                             AuditHealthEvaluatorConfig config)
    : AuditHealthEvaluator(
          health_manager,
          [client = std::move(clickhouse_client)](std::chrono::milliseconds timeout) {
              if (!client) {
                  return false;
              }
              return client->ping(timeout);
          },
          std::move(queue_health_fn), config) {}

AuditHealthEvaluator::AuditHealthEvaluator(common::health::HealthStatusManager& health_manager,
                                             ClickHouseProbeFn clickhouse_probe,
                                             QueueHealthFn queue_health_fn,
                                             AuditHealthEvaluatorConfig config)
    : health_manager_(health_manager),
      clickhouse_probe_(std::move(clickhouse_probe)),
      queue_health_fn_(std::move(queue_health_fn)),
      config_(config) {
    if (config_.auto_start) {
        start();
    }
}

AuditHealthEvaluator::~AuditHealthEvaluator() {
    stop();
}

bool AuditHealthEvaluator::evaluate_once() noexcept {
    bool ch_healthy = false;
    try {
        if (clickhouse_probe_) {
            ch_healthy = clickhouse_probe_(config_.probe_timeout);
        }
    } catch (...) {
        ch_healthy = false;
    }

    if (ch_healthy) {
        consecutive_failures_.store(0, std::memory_order_release);
        is_clickhouse_healthy_.store(true, std::memory_order_release);
    } else {
        uint32_t failures = consecutive_failures_.fetch_add(1, std::memory_order_acq_rel) + 1;
        if (failures >= config_.consecutive_failures_threshold) {
            is_clickhouse_healthy_.store(false, std::memory_order_release);
        }
    }

    bool q_healthy = false;
    uint32_t occupancy_pct = 0;
    try {
        if (queue_health_fn_) {
            bool fn_ok = queue_health_fn_(occupancy_pct);
            q_healthy = fn_ok && (occupancy_pct < config_.queue_high_water_pct);
        } else {
            q_healthy = true;
        }
    } catch (...) {
        q_healthy = false;
    }

    is_queue_healthy_.store(q_healthy, std::memory_order_release);

    bool current_ch = is_clickhouse_healthy_.load(std::memory_order_acquire);
    bool overall_ready = current_ch && q_healthy && !health_manager_.is_shutting_down();

    is_ready_.store(overall_ready, std::memory_order_release);
    health_manager_.set_ready(overall_ready);

    return overall_ready;
}

void AuditHealthEvaluator::start() {
    bool expected = false;
    if (!is_running_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return;
    }

    worker_thread_ = std::thread([this]() {
        while (is_running_.load(std::memory_order_acquire)) {
            evaluate_once();

            std::unique_lock<std::mutex> lock(cv_mutex_);
            cv_.wait_for(lock, config_.check_interval, [this]() {
                return !is_running_.load(std::memory_order_acquire);
            });
        }
    });
}

void AuditHealthEvaluator::stop() noexcept {
    bool expected = true;
    if (!is_running_.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(cv_mutex_);
        cv_.notify_all();
    }

    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

bool AuditHealthEvaluator::is_clickhouse_healthy() const noexcept {
    return is_clickhouse_healthy_.load(std::memory_order_acquire);
}

bool AuditHealthEvaluator::is_queue_healthy() const noexcept {
    return is_queue_healthy_.load(std::memory_order_acquire);
}

bool AuditHealthEvaluator::is_ready() const noexcept {
    return is_ready_.load(std::memory_order_acquire);
}

bool AuditHealthEvaluator::is_running() const noexcept {
    return is_running_.load(std::memory_order_acquire);
}

} // namespace securecloud::audit::health
