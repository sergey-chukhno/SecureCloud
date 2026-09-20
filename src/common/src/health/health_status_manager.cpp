#include "securecloud/health/health_status_manager.hpp"

#include <utility>

namespace securecloud::common::health {

HealthStatusManager::HealthStatusManager(std::string service_name) : service_name_(std::move(service_name)) {}

const std::string& HealthStatusManager::service_name() const noexcept {
    return service_name_;
}

void HealthStatusManager::set_live(bool live) noexcept {
    is_live_.store(live, std::memory_order_release);
}

bool HealthStatusManager::is_live() const noexcept {
    return is_live_.load(std::memory_order_acquire);
}

void HealthStatusManager::set_ready(bool ready) noexcept {
    is_ready_.store(ready, std::memory_order_release);
}

bool HealthStatusManager::is_ready() const noexcept {
    return is_ready_.load(std::memory_order_acquire);
}

void HealthStatusManager::set_shutting_down(bool shutting_down) noexcept {
    is_shutting_down_.store(shutting_down, std::memory_order_release);
}

bool HealthStatusManager::is_shutting_down() const noexcept {
    return is_shutting_down_.load(std::memory_order_acquire);
}

void HealthStatusManager::set_readiness_evaluator(ReadinessEvaluator evaluator) {
    const std::scoped_lock lock(evaluator_mutex_);
    readiness_evaluator_ = std::move(evaluator);
}

bool HealthStatusManager::evaluate_readiness() const noexcept {
    if (!is_live() || !is_ready() || is_shutting_down()) {
        return false;
    }

    ReadinessEvaluator evaluator_copy;
    {
        const std::scoped_lock lock(evaluator_mutex_);
        evaluator_copy = readiness_evaluator_;
    }

    if (evaluator_copy) {
        try {
            return evaluator_copy();
        } catch (...) {
            return false;
        }
    }

    return true;
}

} // namespace securecloud::common::health
