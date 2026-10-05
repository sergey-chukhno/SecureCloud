#include "http/resilience/bulkhead_manager.hpp"

#include "http/errors/error_mapper.hpp"

#include <httplib.h>
#include <utility>

namespace securecloud::gateway::http {

std::string_view to_string(WorkloadCategory category) noexcept {
    switch (category) {
    case WorkloadCategory::Auth:
        return "Auth";
    case WorkloadCategory::Messaging:
        return "Messaging";
    case WorkloadCategory::Files:
        return "Files";
    case WorkloadCategory::Emergency:
        return "Emergency";
    }
    return "Unknown";
}

BulkheadLease::BulkheadLease(WorkloadBulkhead* bulkhead, WorkloadCategory category, bool acquired) noexcept
    : bulkhead_(bulkhead), category_(category), acquired_(acquired) {}

BulkheadLease::~BulkheadLease() noexcept {
    release();
}

BulkheadLease::BulkheadLease(BulkheadLease&& other) noexcept
    : bulkhead_(other.bulkhead_), category_(other.category_), acquired_(other.acquired_) {
    other.bulkhead_ = nullptr;
    other.acquired_ = false;
}

BulkheadLease& BulkheadLease::operator=(BulkheadLease&& other) noexcept {
    if (this != &other) {
        release();
        bulkhead_ = other.bulkhead_;
        category_ = other.category_;
        acquired_ = other.acquired_;
        other.bulkhead_ = nullptr;
        other.acquired_ = false;
    }
    return *this;
}

void BulkheadLease::release() noexcept {
    if (acquired_ && bulkhead_ != nullptr) {
        bulkhead_->release();
        acquired_ = false;
        bulkhead_ = nullptr;
    }
}

WorkloadBulkhead::WorkloadBulkhead(uint32_t max_concurrent) noexcept
    : max_concurrent_(max_concurrent), active_count_(0) {}

bool WorkloadBulkhead::try_acquire() noexcept {
    uint32_t current = active_count_.load(std::memory_order_relaxed);
    while (true) {
        if (current >= max_concurrent_) {
            return false;
        }
        if (active_count_.compare_exchange_weak(current, current + 1, std::memory_order_acquire,
                                                std::memory_order_relaxed)) {
            return true;
        }
    }
}

void WorkloadBulkhead::release() noexcept {
    uint32_t prev = active_count_.fetch_sub(1, std::memory_order_release);
    if (prev == 0) {
        // Protect against underflow in case of unbalanced calls
        active_count_.store(0, std::memory_order_relaxed);
    }
}

uint32_t WorkloadBulkhead::available_slots() const noexcept {
    uint32_t active = active_count_.load(std::memory_order_relaxed);
    return (active < max_concurrent_) ? (max_concurrent_ - active) : 0;
}

BulkheadManager::BulkheadManager(const GatewayBulkheadConfig& config)
    : config_(config), auth_bulkhead_(config.auth_max_concurrent), messaging_bulkhead_(config.messaging_max_concurrent),
      files_bulkhead_(config.files_max_concurrent), emergency_bulkhead_(config.emergency_reserved_slots) {}

WorkloadCategory BulkheadManager::classify_path(std::string_view path) noexcept {
    if (path.rfind("/health", 0) == 0) {
        return WorkloadCategory::Emergency;
    }
    if (path.rfind("/api/v1/messages", 0) == 0) {
        return WorkloadCategory::Messaging;
    }
    if (path.rfind("/api/v1/files", 0) == 0) {
        return WorkloadCategory::Files;
    }
    return WorkloadCategory::Auth;
}

BulkheadLease BulkheadManager::acquire(WorkloadCategory category) {
    auto& bulkhead = get_bulkhead(category);
    bool acquired = bulkhead.try_acquire();
    return BulkheadLease(&bulkhead, category, acquired);
}

BulkheadLease BulkheadManager::acquire_for_path(std::string_view path) {
    return acquire(classify_path(path));
}

BulkheadLease BulkheadManager::acquire(const httplib::Request& req) {
    return acquire_for_path(req.path);
}

void BulkheadManager::write_rejection(httplib::Response& res, const std::string& request_id, uint32_t retry_after_sec) {
    constexpr const char* k_content_type_json = "application/json";
    res.status = 503;
    res.set_header("Retry-After", std::to_string(retry_after_sec));
    res.set_content(ErrorMapper::format_problem_details(
                        503, "https://securecloud.internal/errors/bulkhead-limit-exceeded", "Service Unavailable",
                        "Workload concurrency bulkhead limit exceeded; retry after delay", "BULKHEAD_LIMIT_EXCEEDED",
                        request_id),
                    k_content_type_json);
}

const WorkloadBulkhead& BulkheadManager::get_bulkhead(WorkloadCategory category) const {
    switch (category) {
    case WorkloadCategory::Auth:
        return auth_bulkhead_;
    case WorkloadCategory::Messaging:
        return messaging_bulkhead_;
    case WorkloadCategory::Files:
        return files_bulkhead_;
    case WorkloadCategory::Emergency:
        return emergency_bulkhead_;
    }
    return auth_bulkhead_;
}

WorkloadBulkhead& BulkheadManager::get_bulkhead(WorkloadCategory category) {
    switch (category) {
    case WorkloadCategory::Auth:
        return auth_bulkhead_;
    case WorkloadCategory::Messaging:
        return messaging_bulkhead_;
    case WorkloadCategory::Files:
        return files_bulkhead_;
    case WorkloadCategory::Emergency:
        return emergency_bulkhead_;
    }
    return auth_bulkhead_;
}

uint32_t BulkheadManager::active_count(WorkloadCategory category) const noexcept {
    return get_bulkhead(category).active_count();
}

uint32_t BulkheadManager::max_concurrent(WorkloadCategory category) const noexcept {
    return get_bulkhead(category).max_concurrent();
}

uint32_t BulkheadManager::available_slots(WorkloadCategory category) const noexcept {
    return get_bulkhead(category).available_slots();
}

} // namespace securecloud::gateway::http
