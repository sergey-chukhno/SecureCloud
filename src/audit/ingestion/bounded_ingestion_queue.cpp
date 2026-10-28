#include "ingestion/bounded_ingestion_queue.hpp"

#include <algorithm>

namespace securecloud::audit::ingestion {

BoundedIngestionQueue::BoundedIngestionQueue(size_t capacity) : capacity_(capacity == 0 ? 1 : capacity) {}

BoundedIngestionQueue::~BoundedIngestionQueue() {
    shutdown();
}

bool BoundedIngestionQueue::try_push(IngestionEnvelope item) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (shutdown_ || queue_.size() >= capacity_) {
        total_rejected_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    queue_.push_back(std::move(item));
    const size_t current_size = queue_.size();

    size_t prev_peak = peak_watermark_.load(std::memory_order_relaxed);
    while (current_size > prev_peak &&
           !peak_watermark_.compare_exchange_weak(prev_peak, current_size, std::memory_order_relaxed)) {
    }

    total_enqueued_.fetch_add(1, std::memory_order_relaxed);
    cv_not_empty_.notify_one();
    return true;
}

bool BoundedIngestionQueue::push_with_timeout(IngestionEnvelope item, std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    bool capacity_available =
        cv_not_full_.wait_for(lock, timeout, [this] { return shutdown_ || queue_.size() < capacity_; });

    if (shutdown_ || !capacity_available || queue_.size() >= capacity_) {
        total_rejected_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    queue_.push_back(std::move(item));
    const size_t current_size = queue_.size();

    size_t prev_peak = peak_watermark_.load(std::memory_order_relaxed);
    while (current_size > prev_peak &&
           !peak_watermark_.compare_exchange_weak(prev_peak, current_size, std::memory_order_relaxed)) {
    }

    total_enqueued_.fetch_add(1, std::memory_order_relaxed);
    cv_not_empty_.notify_one();
    return true;
}

std::optional<IngestionEnvelope> BoundedIngestionQueue::pop(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_not_empty_.wait_for(lock, timeout, [this] { return shutdown_ || !queue_.empty(); });

    if (queue_.empty()) {
        return std::nullopt;
    }

    IngestionEnvelope item = std::move(queue_.front());
    queue_.pop_front();
    cv_not_full_.notify_one();
    return item;
}

std::vector<IngestionEnvelope> BoundedIngestionQueue::pop_batch(size_t max_items, std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_not_empty_.wait_for(lock, timeout, [this] { return shutdown_ || !queue_.empty(); });

    if (queue_.empty() || max_items == 0) {
        return {};
    }

    const size_t batch_size = std::min(max_items, queue_.size());
    std::vector<IngestionEnvelope> batch;
    batch.reserve(batch_size);

    for (size_t i = 0; i < batch_size; ++i) {
        batch.push_back(std::move(queue_.front()));
        queue_.pop_front();
    }

    cv_not_full_.notify_all();
    return batch;
}

size_t BoundedIngestionQueue::size() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

size_t BoundedIngestionQueue::capacity() const noexcept {
    return capacity_;
}

bool BoundedIngestionQueue::is_shutdown() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return shutdown_;
}

void BoundedIngestionQueue::shutdown() noexcept {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (shutdown_) {
            return;
        }
        shutdown_ = true;
    }
    cv_not_empty_.notify_all();
    cv_not_full_.notify_all();
}

size_t BoundedIngestionQueue::total_enqueued() const noexcept {
    return total_enqueued_.load(std::memory_order_relaxed);
}

size_t BoundedIngestionQueue::total_rejected() const noexcept {
    return total_rejected_.load(std::memory_order_relaxed);
}

size_t BoundedIngestionQueue::peak_watermark() const noexcept {
    return peak_watermark_.load(std::memory_order_relaxed);
}

grpc::Status create_backpressure_status(grpc::ServerContext* context) {
    if (context != nullptr) {
        context->AddTrailingMetadata("retry-after", "1");
    }
    return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Audit ingestion queue saturated; backpressure applied");
}

} // namespace securecloud::audit::ingestion