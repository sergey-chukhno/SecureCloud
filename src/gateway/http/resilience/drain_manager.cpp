#include "http/resilience/drain_manager.hpp"

#include "securecloud/health/health_status_manager.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <utility>

namespace securecloud::gateway::http {

// --- DrainLease Implementation ---

DrainLease::DrainLease(std::shared_ptr<DrainManager> manager) noexcept : manager_(std::move(manager)) {}

DrainLease::~DrainLease() noexcept {
    release();
}

DrainLease::DrainLease(DrainLease&& other) noexcept : manager_(std::move(other.manager_)) {
    other.manager_ = nullptr;
}

DrainLease& DrainLease::operator=(DrainLease&& other) noexcept {
    if (this != &other) {
        release();
        manager_ = std::move(other.manager_);
        other.manager_ = nullptr;
    }
    return *this;
}

void DrainLease::release() noexcept {
    if (manager_) {
        manager_->decrement_in_flight();
        manager_ = nullptr;
    }
}

// --- DrainManager Implementation ---

DrainManager::DrainManager(common::health::HealthStatusManager* health_manager) : health_manager_(health_manager) {}

DrainManager::DrainManager(std::shared_ptr<common::health::HealthStatusManager> health_manager)
    : health_manager_ptr_(std::move(health_manager)), health_manager_(health_manager_ptr_.get()) {}

bool DrainManager::try_acquire(DrainLease& out_lease) {
    if (is_draining_.load(std::memory_order_acquire)) {
        return false;
    }

    in_flight_requests_.fetch_add(1, std::memory_order_relaxed);

    // Double-check after increment to prevent race with start_drain()
    if (is_draining_.load(std::memory_order_acquire)) {
        decrement_in_flight();
        return false;
    }

    out_lease = DrainLease(shared_from_this());
    return true;
}

void DrainManager::decrement_in_flight() noexcept {
    size_t prev = in_flight_requests_.fetch_sub(1, std::memory_order_release);
    if (prev <= 1) {
        std::lock_guard<std::mutex> lock(cv_mutex_);
        cv_.notify_all();
    }
}

bool DrainManager::start_drain(std::chrono::milliseconds timeout) {
    is_draining_.store(true, std::memory_order_release);

    if (health_manager_) {
        health_manager_->set_shutting_down(true);
        health_manager_->set_ready(false);
    }

    std::unique_lock<std::mutex> lock(cv_mutex_);
    if (in_flight_requests_.load(std::memory_order_acquire) == 0) {
        return true;
    }

    return cv_.wait_for(lock, timeout, [this] { return in_flight_requests_.load(std::memory_order_acquire) == 0; });
}

bool DrainManager::is_draining() const noexcept {
    return is_draining_.load(std::memory_order_acquire);
}

size_t DrainManager::in_flight_count() const noexcept {
    return in_flight_requests_.load(std::memory_order_relaxed);
}

void DrainManager::write_rejection(httplib::Response& res, const std::string& request_id, uint32_t retry_after_sec) {
    res.status = 503;
    res.set_header(k_header_retry_after, std::to_string(retry_after_sec));
    res.set_header("Connection", "close");

    nlohmann::json problem = {{"type", "https://securecloud.internal/errors/server-shutting-down"},
                              {"title", "Server Shutting Down"},
                              {"status", 503},
                              {"detail", "Server is undergoing graceful shutdown and cannot accept new requests"},
                              {"error", {{"code", "SERVER_SHUTTING_DOWN"}}}};

    if (!request_id.empty()) {
        problem["request_id"] = request_id;
    }

    res.set_content(problem.dump(), k_content_type_problem_json);
}

} // namespace securecloud::gateway::http
