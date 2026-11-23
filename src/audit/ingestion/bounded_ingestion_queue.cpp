#include "ingestion/bounded_ingestion_queue.hpp"

#include "telemetry/audit_metrics.hpp"

#include <algorithm>

namespace securecloud::audit::ingestion {

namespace {

telemetry::ProducerLabel map_producer_label(domain::ProducerService producer) noexcept {
    switch (producer) {
    case domain::ProducerService::Gateway:
        return telemetry::ProducerLabel::Gateway;
    case domain::ProducerService::Auth:
        return telemetry::ProducerLabel::Auth;
    case domain::ProducerService::Messaging:
        return telemetry::ProducerLabel::Messaging;
    case domain::ProducerService::Files:
        return telemetry::ProducerLabel::Files;
    case domain::ProducerService::Audit:
        return telemetry::ProducerLabel::Audit;
    default:
        return telemetry::ProducerLabel::Unknown;
    }
}

} // namespace

BoundedIngestionQueue::BoundedIngestionQueue(size_t capacity) : capacity_(capacity == 0 ? 1 : capacity) {
    telemetry::AuditMetrics::instance().set_queue_capacity(static_cast<int64_t>(capacity_));
    telemetry::AuditMetrics::instance().set_queue_depth(0);
}

BoundedIngestionQueue::~BoundedIngestionQueue() {
    shutdown();
}

void BoundedIngestionQueue::record_enqueue_metrics_locked(const IngestionEnvelope& item) {
    (void)item;
    const size_t current_size = queue_.size();
    telemetry::AuditMetrics::instance().set_queue_depth(static_cast<int64_t>(current_size));
}

void BoundedIngestionQueue::record_pop_metrics_locked(const IngestionEnvelope& item) {
    const size_t current_size = queue_.size();
    telemetry::AuditMetrics::instance().set_queue_depth(static_cast<int64_t>(current_size));

    auto now = std::chrono::system_clock::now();
    auto wait_duration = std::chrono::duration<double>(now - item.enqueued_at).count();
    if (wait_duration >= 0.0) {
        telemetry::AuditMetrics::instance().observe_queue_wait_duration(wait_duration);
    }
}

bool BoundedIngestionQueue::try_push(IngestionEnvelope item) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (shutdown_ || queue_.size() >= capacity_) {
        total_rejected_.fetch_add(1, std::memory_order_relaxed);
        auto producer_lbl = map_producer_label(item.event.producer_service);
        telemetry::AuditMetrics::instance().record_queue_saturated_drop(producer_lbl);
        return false;
    }

    queue_.push_back(std::move(item));
    record_enqueue_metrics_locked(queue_.back());

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
        auto producer_lbl = map_producer_label(item.event.producer_service);
        telemetry::AuditMetrics::instance().record_queue_saturated_drop(producer_lbl);
        return false;
    }

    queue_.push_back(std::move(item));
    record_enqueue_metrics_locked(queue_.back());

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
    record_pop_metrics_locked(item);

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
        record_pop_metrics_locked(batch.back());
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
