#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

namespace httplib {
struct Response;
} // namespace httplib

namespace securecloud::common::health {
class HealthStatusManager;
} // namespace securecloud::common::health

namespace securecloud::gateway::http {

class DrainManager;

/// RAII lease guaranteeing in-flight request count decrement and drain notification upon completion.
class DrainLease {
  public:
    DrainLease() noexcept = default;
    explicit DrainLease(std::shared_ptr<DrainManager> manager) noexcept;
    ~DrainLease() noexcept;

    DrainLease(const DrainLease&) = delete;
    DrainLease& operator=(const DrainLease&) = delete;
    DrainLease(DrainLease&& other) noexcept;
    DrainLease& operator=(DrainLease&& other) noexcept;

    [[nodiscard]] bool valid() const noexcept { return manager_ != nullptr; }
    explicit operator bool() const noexcept { return valid(); }

    void release() noexcept;

  private:
    std::shared_ptr<DrainManager> manager_{nullptr};
};

/// Coordinated graceful drain manager (ADR-009, GW-009-T04).
/// Ensures that upon shutdown signal (SIGINT/SIGTERM):
/// 1. Health readiness immediately drops to NOT_SERVING so upstream balancers detach the gateway.
/// 2. New inbound non-health requests are rejected with HTTP 503 SERVER_SHUTTING_DOWN.
/// 3. In-flight requests are tracked and permitted to finish cleanly within a bounded drain timeout.
class DrainManager : public std::enable_shared_from_this<DrainManager> {
  public:
    static constexpr const char* k_content_type_problem_json = "application/problem+json";
    static constexpr const char* k_header_retry_after = "Retry-After";
    static constexpr uint32_t k_default_retry_after_sec = 5;

    explicit DrainManager(common::health::HealthStatusManager* health_manager = nullptr);
    explicit DrainManager(std::shared_ptr<common::health::HealthStatusManager> health_manager);
    ~DrainManager() = default;

    DrainManager(const DrainManager&) = delete;
    DrainManager& operator=(const DrainManager&) = delete;
    DrainManager(DrainManager&&) = delete;
    DrainManager& operator=(DrainManager&&) = delete;

    /// Attempts to acquire a drain lease for an in-flight request.
    /// If the gateway is currently draining, returns false and an invalid lease.
    [[nodiscard]] bool try_acquire(DrainLease& out_lease);

    /// Initiates graceful drain:
    /// 1. Marks is_draining to true.
    /// 2. If health_manager is present, sets shutting_down=true and ready=false.
    /// 3. Awaits completion of in-flight requests until timeout expires.
    /// Returns true if all in-flight requests completed before timeout, false if timeout expired.
    bool start_drain(std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));

    [[nodiscard]] bool is_draining() const noexcept;
    [[nodiscard]] size_t in_flight_count() const noexcept;

    /// Emits RFC 7807 problem details response for rejected requests during drain.
    static void write_rejection(httplib::Response& res, const std::string& request_id,
                                uint32_t retry_after_sec = k_default_retry_after_sec);

  private:
    friend class DrainLease;
    void decrement_in_flight() noexcept;

    std::shared_ptr<common::health::HealthStatusManager> health_manager_ptr_{nullptr};
    common::health::HealthStatusManager* health_manager_{nullptr};
    std::atomic<bool> is_draining_{false};
    std::atomic<size_t> in_flight_requests_{0};

    mutable std::mutex cv_mutex_;
    std::condition_variable cv_;
};

} // namespace securecloud::gateway::http
