#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>

namespace securecloud::files {

class ConcurrencyBulkhead;

/// RAII permit handle that automatically releases its permit upon destruction.
class BulkheadPermit {
  public:
    BulkheadPermit() noexcept = default;
    explicit BulkheadPermit(std::shared_ptr<ConcurrencyBulkhead> bulkhead) noexcept;
    ~BulkheadPermit();

    BulkheadPermit(const BulkheadPermit&) = delete;
    BulkheadPermit& operator=(const BulkheadPermit&) = delete;

    BulkheadPermit(BulkheadPermit&& other) noexcept;
    BulkheadPermit& operator=(BulkheadPermit&& other) noexcept;

    /// Explicitly release the permit before destruction.
    void release() noexcept;

    /// Checks if this handle holds an active permit.
    [[nodiscard]] bool holds_permit() const noexcept;
    explicit operator bool() const noexcept { return holds_permit(); }

  private:
    std::shared_ptr<ConcurrencyBulkhead> bulkhead_{nullptr};
};

/// Thread-safe bounded concurrency bulkhead (ADR-009, FILES-009).
/// Isolates execution domains and prevents resource starvation across workloads.
class ConcurrencyBulkhead : public std::enable_shared_from_this<ConcurrencyBulkhead> {
  public:
    explicit ConcurrencyBulkhead(std::string domain_name,
                                 size_t max_concurrency,
                                 std::chrono::milliseconds acquire_timeout = std::chrono::milliseconds(500));
    ~ConcurrencyBulkhead() = default;

    ConcurrencyBulkhead(const ConcurrencyBulkhead&) = delete;
    ConcurrencyBulkhead& operator=(const ConcurrencyBulkhead&) = delete;

    /// Factory method to create a shared ConcurrencyBulkhead instance.
    static std::shared_ptr<ConcurrencyBulkhead> create(std::string domain_name,
                                                       size_t max_concurrency,
                                                       std::chrono::milliseconds acquire_timeout = std::chrono::milliseconds(500));

    /// Try to acquire a permit immediately without blocking.
    /// Returns a valid BulkheadPermit if acquired, or an empty BulkheadPermit if saturated.
    [[nodiscard]] BulkheadPermit try_acquire();

    /// Try to acquire a permit, waiting up to the configured or specified timeout.
    /// Returns a valid BulkheadPermit if acquired, or an empty BulkheadPermit if timed out.
    [[nodiscard]] BulkheadPermit acquire_with_timeout(std::chrono::milliseconds timeout);
    [[nodiscard]] BulkheadPermit acquire_with_default_timeout();

    /// Releases a permit back to the bulkhead. Called automatically by BulkheadPermit.
    void release_permit() noexcept;

    /// Current count of active/in-flight permits.
    [[nodiscard]] size_t active_permits() const noexcept;

    /// Maximum concurrency allowed for this domain.
    [[nodiscard]] size_t max_concurrency() const noexcept;

    /// Available permits remaining.
    [[nodiscard]] size_t available_permits() const noexcept;

    /// Domain name identifier.
    [[nodiscard]] const std::string& domain_name() const noexcept;

    /// Default acquire timeout.
    [[nodiscard]] std::chrono::milliseconds default_timeout() const noexcept;

  private:
    const std::string domain_name_;
    const size_t max_concurrency_;
    const std::chrono::milliseconds acquire_timeout_;

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    size_t active_permits_{0};
};

} // namespace securecloud::files
