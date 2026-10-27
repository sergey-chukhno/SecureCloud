#include "concurrency_bulkhead.hpp"

#include <utility>

namespace securecloud::files {

BulkheadPermit::BulkheadPermit(std::shared_ptr<ConcurrencyBulkhead> bulkhead) noexcept
    : bulkhead_(std::move(bulkhead)) {}

BulkheadPermit::~BulkheadPermit() {
    release();
}

BulkheadPermit::BulkheadPermit(BulkheadPermit&& other) noexcept
    : bulkhead_(std::move(other.bulkhead_)) {
    other.bulkhead_ = nullptr;
}

BulkheadPermit& BulkheadPermit::operator=(BulkheadPermit&& other) noexcept {
    if (this != &other) {
        release();
        bulkhead_ = std::move(other.bulkhead_);
        other.bulkhead_ = nullptr;
    }
    return *this;
}

void BulkheadPermit::release() noexcept {
    if (bulkhead_) {
        bulkhead_->release_permit();
        bulkhead_ = nullptr;
    }
}

bool BulkheadPermit::holds_permit() const noexcept {
    return bulkhead_ != nullptr;
}

ConcurrencyBulkhead::ConcurrencyBulkhead(std::string domain_name,
                                         size_t max_concurrency,
                                         std::chrono::milliseconds acquire_timeout)
    : domain_name_(std::move(domain_name)),
      max_concurrency_(max_concurrency > 0 ? max_concurrency : 1),
      acquire_timeout_(acquire_timeout) {}

std::shared_ptr<ConcurrencyBulkhead> ConcurrencyBulkhead::create(std::string domain_name,
                                                                 size_t max_concurrency,
                                                                 std::chrono::milliseconds acquire_timeout) {
    return std::make_shared<ConcurrencyBulkhead>(std::move(domain_name), max_concurrency, acquire_timeout);
}

BulkheadPermit ConcurrencyBulkhead::try_acquire() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (active_permits_ < max_concurrency_) {
        ++active_permits_;
        return BulkheadPermit(shared_from_this());
    }
    return BulkheadPermit();
}

BulkheadPermit ConcurrencyBulkhead::acquire_with_timeout(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (active_permits_ < max_concurrency_) {
        ++active_permits_;
        return BulkheadPermit(shared_from_this());
    }

    bool acquired = cv_.wait_for(lock, timeout, [this] {
        return active_permits_ < max_concurrency_;
    });

    if (acquired) {
        ++active_permits_;
        return BulkheadPermit(shared_from_this());
    }

    return BulkheadPermit();
}

BulkheadPermit ConcurrencyBulkhead::acquire_with_default_timeout() {
    return acquire_with_timeout(acquire_timeout_);
}

void ConcurrencyBulkhead::release_permit() noexcept {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (active_permits_ > 0) {
            --active_permits_;
        }
    }
    cv_.notify_one();
}

size_t ConcurrencyBulkhead::active_permits() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_permits_;
}

size_t ConcurrencyBulkhead::max_concurrency() const noexcept {
    return max_concurrency_;
}

size_t ConcurrencyBulkhead::available_permits() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (active_permits_ >= max_concurrency_) {
        return 0;
    }
    return max_concurrency_ - active_permits_;
}

const std::string& ConcurrencyBulkhead::domain_name() const noexcept {
    return domain_name_;
}

std::chrono::milliseconds ConcurrencyBulkhead::default_timeout() const noexcept {
    return acquire_timeout_;
}

} // namespace securecloud::files
