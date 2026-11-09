#include "health/audit_health_evaluator.hpp"

#include "telemetry/audit_metrics.hpp"

#include <exception>
#include <iostream>
#include <utility>

namespace securecloud::audit::health {

AuditHealthEvaluator::AuditHealthEvaluator(common::health::HealthStatusManager& health_manager,
                                           std::shared_ptr<repository::ClickHouseClient> clickhouse_client,
                                           QueueHealthFn queue_health_fn, AuditHealthEvaluatorConfig config)
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
                                           ClickHouseProbeFn clickhouse_probe, QueueHealthFn queue_health_fn,
                                           AuditHealthEvaluatorConfig config)
    : health_manager_(health_manager), clickhouse_probe_(std::move(clickhouse_probe)),
      queue_health_fn_(std::move(queue_health_fn)), config_(config) {
    if (config_.auto_start) {
        start();
    }
}

AuditHealthEvaluator::~AuditHealthEvaluator() {
    stop();
}

void AuditHealthEvaluator::update_state(lifecycle::DetailedServiceState new_state,
                                        lifecycle::StateTransitionReason reason) noexcept {
    auto current = detailed_state_.load(std::memory_order_acquire);
    if (current != new_state) {
        detailed_state_.store(new_state, std::memory_order_release);
        last_transition_reason_.store(reason, std::memory_order_release);
        std::cout << "[SecureCloud] [audit] Service state transition: " << lifecycle::to_string(current) << " -> "
                  << lifecycle::to_string(new_state) << " (Reason: " << lifecycle::to_string(reason) << ")\n";
    }
}

bool AuditHealthEvaluator::evaluate_once() noexcept {
    // Capture previous states prior to evaluation
    bool prev_ch_healthy = is_clickhouse_healthy_.load(std::memory_order_acquire);
    bool prev_q_saturated = is_queue_saturated_.load(std::memory_order_acquire);

    // 1. ClickHouse probe with hysteresis
    bool ch_probe_ok = false;
    try {
        if (clickhouse_probe_) {
            ch_probe_ok = clickhouse_probe_(config_.probe_timeout);
        }
    } catch (...) {
        ch_probe_ok = false;
    }

    if (ch_probe_ok) {
        consecutive_failures_.store(0, std::memory_order_release);
        uint32_t succ = consecutive_successes_.fetch_add(1, std::memory_order_acq_rel) + 1;
        if (succ >= config_.consecutive_successes_threshold) {
            is_clickhouse_healthy_.store(true, std::memory_order_release);
        }
    } else {
        consecutive_successes_.store(0, std::memory_order_release);
        uint32_t fail = consecutive_failures_.fetch_add(1, std::memory_order_acq_rel) + 1;
        if (fail >= config_.consecutive_failures_threshold) {
            is_clickhouse_healthy_.store(false, std::memory_order_release);
        }
    }

    // 2. Queue occupancy with hysteresis (high water >= 90%, low water < 80%)
    uint32_t occupancy_pct = 0;
    bool q_fn_ok = false;
    try {
        if (queue_health_fn_) {
            q_fn_ok = queue_health_fn_(occupancy_pct);
        } else {
            q_fn_ok = true;
            occupancy_pct = 0;
        }
    } catch (...) {
        q_fn_ok = false;
    }

    if (!q_fn_ok || occupancy_pct >= config_.queue_high_water_pct) {
        is_queue_saturated_.store(true, std::memory_order_release);
    } else if (occupancy_pct < config_.queue_low_water_pct) {
        is_queue_saturated_.store(false, std::memory_order_release);
    }

    bool ch_healthy = is_clickhouse_healthy_.load(std::memory_order_acquire);
    telemetry::AuditMetrics::instance().set_clickhouse_available(ch_healthy);

    bool q_saturated = is_queue_saturated_.load(std::memory_order_acquire);
    bool is_shutting_down = health_manager_.is_shutting_down();

    lifecycle::DetailedServiceState next_state = lifecycle::DetailedServiceState::Ready;
    lifecycle::StateTransitionReason transition_reason = lifecycle::StateTransitionReason::None;

    if (is_shutting_down) {
        next_state = lifecycle::DetailedServiceState::Draining;
        transition_reason = lifecycle::StateTransitionReason::ShutdownRequested;
    } else if (!ch_healthy && q_saturated) {
        next_state = lifecycle::DetailedServiceState::NotReady;
        transition_reason = lifecycle::StateTransitionReason::ClickHouseAndQueueFailure;
    } else if (!ch_healthy) {
        next_state = lifecycle::DetailedServiceState::Degraded;
        transition_reason = lifecycle::StateTransitionReason::ClickHousePingTimeout;
    } else if (q_saturated) {
        next_state = lifecycle::DetailedServiceState::Degraded;
        transition_reason = lifecycle::StateTransitionReason::QueueSaturated;
    } else {
        next_state = lifecycle::DetailedServiceState::Ready;
        if (prev_q_saturated && !q_saturated) {
            transition_reason = lifecycle::StateTransitionReason::QueueDrained;
        } else if (!prev_ch_healthy && ch_healthy) {
            transition_reason = lifecycle::StateTransitionReason::ClickHouseRecovered;
        } else {
            transition_reason = lifecycle::StateTransitionReason::None;
        }
    }

    update_state(next_state, transition_reason);

    bool overall_ready = (next_state == lifecycle::DetailedServiceState::Ready);
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
            cv_.wait_for(lock, config_.check_interval,
                         [this]() { return !is_running_.load(std::memory_order_acquire); });
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
    return !is_queue_saturated_.load(std::memory_order_acquire);
}

bool AuditHealthEvaluator::is_ready() const noexcept {
    return is_ready_.load(std::memory_order_acquire);
}

bool AuditHealthEvaluator::is_running() const noexcept {
    return is_running_.load(std::memory_order_acquire);
}

lifecycle::DetailedServiceState AuditHealthEvaluator::detailed_state() const noexcept {
    return detailed_state_.load(std::memory_order_acquire);
}

lifecycle::StateTransitionReason AuditHealthEvaluator::last_transition_reason() const noexcept {
    return last_transition_reason_.load(std::memory_order_acquire);
}

} // namespace securecloud::audit::health
