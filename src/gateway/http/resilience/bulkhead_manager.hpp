#pragma once

#include "gateway_config.hpp"

#include <atomic>
#include <cstdint>
#include <string>
#include <string_view>

namespace httplib {
struct Request;
struct Response;
} // namespace httplib

namespace securecloud::gateway::http {

/**
 * @brief Categorization of API Gateway workloads for bulkhead concurrency partitioning (ADR-009 Section 9).
 */
enum class WorkloadCategory {
    Auth,      ///< Authentication, token lifecycle, device registration, and user identity
    Messaging, ///< Real-time messaging, inbox queries, conversation updates
    Files,     ///< File uploads, downloads, and chunked transfer operations
    Emergency  ///< Reserved perimeter capacity for health checks and operational probes (not a microservice)
};

[[nodiscard]] std::string_view to_string(WorkloadCategory category) noexcept;

class WorkloadBulkhead;

/**
 * @brief RAII lease object representing an acquired concurrency slot in a workload bulkhead.
 *
 * Move-only. Releases the slot back to the underlying WorkloadBulkhead upon destruction or explicit release().
 */
class BulkheadLease {
  public:
    BulkheadLease() noexcept = default;
    BulkheadLease(WorkloadBulkhead* bulkhead, WorkloadCategory category, bool acquired) noexcept;

    ~BulkheadLease() noexcept;

    BulkheadLease(const BulkheadLease&) = delete;
    BulkheadLease& operator=(const BulkheadLease&) = delete;

    BulkheadLease(BulkheadLease&& other) noexcept;
    BulkheadLease& operator=(BulkheadLease&& other) noexcept;

    /// Releases the acquired slot back to the bulkhead immediately.
    void release() noexcept;

    /// Returns true if a concurrency slot was successfully acquired.
    [[nodiscard]] bool is_acquired() const noexcept { return acquired_; }

    /// Contextual boolean conversion operator.
    [[nodiscard]] explicit operator bool() const noexcept { return acquired_; }

    /// Returns the workload category associated with this lease.
    [[nodiscard]] WorkloadCategory category() const noexcept { return category_; }

  private:
    WorkloadBulkhead* bulkhead_{nullptr};
    WorkloadCategory category_{WorkloadCategory::Auth};
    bool acquired_{false};
};

/**
 * @brief Thread-safe concurrency counter with lock-free atomic reservation.
 */
class WorkloadBulkhead {
  public:
    explicit WorkloadBulkhead(uint32_t max_concurrent = 0) noexcept;

    WorkloadBulkhead(const WorkloadBulkhead&) = delete;
    WorkloadBulkhead& operator=(const WorkloadBulkhead&) = delete;
    WorkloadBulkhead(WorkloadBulkhead&&) = delete;
    WorkloadBulkhead& operator=(WorkloadBulkhead&&) = delete;

    /// Attempts to atomically reserve a concurrency slot. Returns true if acquired.
    [[nodiscard]] bool try_acquire() noexcept;

    /// Releases a previously acquired slot, decrementing the active count.
    void release() noexcept;

    /// Returns current active (in-flight) concurrency count.
    [[nodiscard]] uint32_t active_count() const noexcept { return active_count_.load(std::memory_order_relaxed); }

    /// Returns configured maximum concurrent capacity.
    [[nodiscard]] uint32_t max_concurrent() const noexcept { return max_concurrent_; }

    /// Returns the number of currently available slots.
    [[nodiscard]] uint32_t available_slots() const noexcept;

    /// Updates the maximum concurrent limit.
    void set_max_concurrent(uint32_t max_concurrent) noexcept { max_concurrent_ = max_concurrent; }

  private:
    uint32_t max_concurrent_{0};
    std::atomic<uint32_t> active_count_{0};
};

/**
 * @brief Central bulkhead manager coordinating isolated concurrency pools across workloads.
 *
 * Implements Workload Bulkhead Concurrency Partitioning (ADR-009 Section 9, GW-009-T01).
 * Isolates Auth, Messaging, Files, and Emergency traffic so high-load workloads cannot starve
 * critical perimeter authentication or health monitoring.
 */
class BulkheadManager {
  public:
    explicit BulkheadManager(const GatewayBulkheadConfig& config = {});
    ~BulkheadManager() = default;

    BulkheadManager(const BulkheadManager&) = delete;
    BulkheadManager& operator=(const BulkheadManager&) = delete;
    BulkheadManager(BulkheadManager&&) = delete;
    BulkheadManager& operator=(BulkheadManager&&) = delete;

    /// Attempts to acquire a lease for a specific workload category.
    [[nodiscard]] BulkheadLease acquire(WorkloadCategory category);

    /// Maps request URI to workload category and attempts to acquire a lease.
    [[nodiscard]] BulkheadLease acquire(const httplib::Request& req);

    /// Maps a raw path to workload category and attempts to acquire a lease.
    [[nodiscard]] BulkheadLease acquire_for_path(std::string_view path);

    /// Classifies an HTTP request path into its corresponding WorkloadCategory.
    [[nodiscard]] static WorkloadCategory classify_path(std::string_view path) noexcept;

    /// Writes standardized RFC 7807 problem details response for bulkhead limit exceeded (HTTP 503).
    static void write_rejection(httplib::Response& res, const std::string& request_id = "",
                                uint32_t retry_after_sec = 5);

    /// Returns the underlying WorkloadBulkhead for a given category.
    [[nodiscard]] const WorkloadBulkhead& get_bulkhead(WorkloadCategory category) const;

    /// Returns mutable WorkloadBulkhead for a given category (e.g. for dynamic reconfiguration or testing).
    [[nodiscard]] WorkloadBulkhead& get_bulkhead(WorkloadCategory category);

    /// Returns current active concurrency for a workload category.
    [[nodiscard]] uint32_t active_count(WorkloadCategory category) const noexcept;

    /// Returns maximum capacity for a workload category.
    [[nodiscard]] uint32_t max_concurrent(WorkloadCategory category) const noexcept;

    /// Returns available capacity for a workload category.
    [[nodiscard]] uint32_t available_slots(WorkloadCategory category) const noexcept;

    /// Returns the configured bulkhead settings.
    [[nodiscard]] const GatewayBulkheadConfig& config() const noexcept { return config_; }

  private:
    GatewayBulkheadConfig config_;
    WorkloadBulkhead auth_bulkhead_;
    WorkloadBulkhead messaging_bulkhead_;
    WorkloadBulkhead files_bulkhead_;
    WorkloadBulkhead emergency_bulkhead_;
};

} // namespace securecloud::gateway::http
