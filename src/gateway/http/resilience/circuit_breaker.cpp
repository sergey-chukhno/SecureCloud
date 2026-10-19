#include "http/resilience/circuit_breaker.hpp"

#include <algorithm>
#include <chrono>
#include <httplib.h>
#include <nlohmann/json.hpp>

namespace securecloud::gateway::http {

std::string_view to_string(CircuitState state) noexcept {
    switch (state) {
    case CircuitState::Closed:
        return "CLOSED";
    case CircuitState::Open:
        return "OPEN";
    case CircuitState::HalfOpen:
        return "HALF_OPEN";
    }
    return "UNKNOWN";
}

bool CircuitBreaker::is_transient_failure(::grpc::StatusCode status) noexcept {
    return status == ::grpc::StatusCode::UNAVAILABLE || status == ::grpc::StatusCode::DEADLINE_EXCEEDED;
}

CircuitBreaker::CircuitBreaker(std::string service_name, GatewayCircuitBreakerConfig config, ClockFn clock_fn) noexcept
    : service_name_(std::move(service_name)), config_(config), clock_fn_(std::move(clock_fn)) {}

std::chrono::steady_clock::time_point CircuitBreaker::now() const {
    if (clock_fn_) {
        return clock_fn_();
    }
    return std::chrono::steady_clock::now();
}

bool CircuitBreaker::allow_request() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!config_.enabled) {
        return true;
    }

    const auto current_tp = now();

    if (state_ == CircuitState::Closed) {
        return true;
    }

    if (state_ == CircuitState::Open) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current_tp - open_time_).count();
        if (elapsed >= static_cast<int64_t>(config_.recovery_timeout_ms)) {
            // Transition from Open to HalfOpen and permit probe request
            state_ = CircuitState::HalfOpen;
            half_open_probes_in_flight_ = 1;
            return true;
        }
        // Still within Open recovery window -> fail fast at perimeter
        return false;
    }

    // state_ == CircuitState::HalfOpen
    if (half_open_probes_in_flight_ < config_.half_open_probe_count) {
        ++half_open_probes_in_flight_;
        return true;
    }

    return false;
}

void CircuitBreaker::record_success() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!config_.enabled) {
        return;
    }

    if (state_ == CircuitState::HalfOpen) {
        state_ = CircuitState::Closed;
        consecutive_failures_ = 0;
        half_open_probes_in_flight_ = 0;
    } else if (state_ == CircuitState::Closed) {
        consecutive_failures_ = 0;
    }
}

void CircuitBreaker::record_failure(bool is_transient_failure) {
    if (!is_transient_failure) {
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    if (!config_.enabled) {
        return;
    }

    const auto current_tp = now();

    if (state_ == CircuitState::HalfOpen) {
        // Failed probe immediately reverts back to Open
        state_ = CircuitState::Open;
        open_time_ = current_tp;
        half_open_probes_in_flight_ = 0;
    } else if (state_ == CircuitState::Closed) {
        ++consecutive_failures_;
        if (consecutive_failures_ >= config_.failure_threshold) {
            state_ = CircuitState::Open;
            open_time_ = current_tp;
            half_open_probes_in_flight_ = 0;
        }
    }
}

void CircuitBreaker::record_status(::grpc::StatusCode status) {
    if (status == ::grpc::StatusCode::OK) {
        record_success();
    } else {
        record_failure(is_transient_failure(status));
    }
}

CircuitState CircuitBreaker::state() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == CircuitState::Open) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now() - open_time_).count();
        if (elapsed >= static_cast<int64_t>(config_.recovery_timeout_ms)) {
            return CircuitState::HalfOpen;
        }
    }
    return state_;
}

uint32_t CircuitBreaker::consecutive_failures() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return consecutive_failures_;
}

uint32_t CircuitBreaker::remaining_recovery_time_sec() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != CircuitState::Open) {
        return 0;
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now() - open_time_).count();
    if (elapsed >= static_cast<int64_t>(config_.recovery_timeout_ms)) {
        return 0;
    }
    const auto remaining_ms = static_cast<uint64_t>(config_.recovery_timeout_ms - elapsed);
    return static_cast<uint32_t>((remaining_ms + 999) / 1000);
}

void CircuitBreaker::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    state_ = CircuitState::Closed;
    consecutive_failures_ = 0;
    half_open_probes_in_flight_ = 0;
}

void CircuitBreaker::write_rejection(httplib::Response& res, const std::string& request_id, uint32_t retry_after_sec) {
    res.status = 503;
    res.set_header("Retry-After", std::to_string(std::max<uint32_t>(1, retry_after_sec)));

    nlohmann::json problem = {
        {"type", "https://securecloud.internal/errors/circuit-breaker-open"},
        {"title", "Service Unavailable"},
        {"status", 503},
        {"error",
         {{"code", "CIRCUIT_BREAKER_OPEN"}, {"message", "Downstream service circuit breaker is open; failing fast"}}},
        {"request_id", request_id}};

    res.set_content(problem.dump(), "application/problem+json");
}

CircuitBreakerRegistry::CircuitBreakerRegistry(GatewayCircuitBreakerConfig default_config,
                                               CircuitBreaker::ClockFn clock_fn)
    : default_config_(default_config), clock_fn_(std::move(clock_fn)) {
    (void)get_or_create("auth");
    (void)get_or_create("messaging");
    (void)get_or_create("files");
    (void)get_or_create("audit");
}

std::shared_ptr<CircuitBreaker> CircuitBreakerRegistry::get(const std::string& service_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = breakers_.find(service_name);
    if (it != breakers_.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<CircuitBreaker> CircuitBreakerRegistry::get_or_create(const std::string& service_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = breakers_.find(service_name);
    if (it != breakers_.end()) {
        return it->second;
    }
    auto cb = std::make_shared<CircuitBreaker>(service_name, default_config_, clock_fn_);
    breakers_[service_name] = cb;
    return cb;
}

void CircuitBreakerRegistry::reset_all() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [name, cb] : breakers_) {
        cb->reset();
    }
}

} // namespace securecloud::gateway::http
