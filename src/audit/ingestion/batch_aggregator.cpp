#include "ingestion/batch_aggregator.hpp"

namespace securecloud::audit::ingestion {

// --- BoundedBatchQueue Implementation ---

BoundedBatchQueue::BoundedBatchQueue(size_t capacity) : capacity_(capacity == 0 ? 1 : capacity) {}

BoundedBatchQueue::~BoundedBatchQueue() {
    shutdown();
}

bool BoundedBatchQueue::try_push(IngestionBatch batch) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (shutdown_ || queue_.size() >= capacity_) {
        return false;
    }
    queue_.push_back(std::move(batch));
    cv_not_empty_.notify_one();
    return true;
}

bool BoundedBatchQueue::push_with_timeout(IngestionBatch batch, std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    bool capacity_available =
        cv_not_full_.wait_for(lock, timeout, [this] { return shutdown_ || queue_.size() < capacity_; });

    if (shutdown_ || !capacity_available || queue_.size() >= capacity_) {
        return false;
    }

    queue_.push_back(std::move(batch));
    cv_not_empty_.notify_one();
    return true;
}

std::optional<IngestionBatch> BoundedBatchQueue::pop(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_not_empty_.wait_for(lock, timeout, [this] { return shutdown_ || !queue_.empty(); });

    if (queue_.empty()) {
        return std::nullopt;
    }

    IngestionBatch batch = std::move(queue_.front());
    queue_.pop_front();
    cv_not_full_.notify_one();
    return batch;
}

size_t BoundedBatchQueue::size() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

size_t BoundedBatchQueue::capacity() const noexcept {
    return capacity_;
}

bool BoundedBatchQueue::is_shutdown() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return shutdown_;
}

void BoundedBatchQueue::shutdown() noexcept {
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

// --- BatchAggregator Implementation ---

BatchAggregator::BatchAggregator(size_t max_batch_size, std::chrono::milliseconds max_batch_delay,
                                 std::shared_ptr<BoundedIngestionQueue> input_queue,
                                 std::shared_ptr<BoundedBatchQueue> output_batch_queue)
    : max_batch_size_(max_batch_size == 0 ? 1000 : max_batch_size), max_batch_delay_(max_batch_delay),
      input_queue_(std::move(input_queue)), output_batch_queue_(std::move(output_batch_queue)) {
    active_batch_.reserve(max_batch_size_);
}

BatchAggregator::~BatchAggregator() {
    stop();
}

void BatchAggregator::start() {
    if (running_.exchange(true)) {
        return;
    }
    worker_thread_ = std::thread(&BatchAggregator::aggregator_loop, this);
}

void BatchAggregator::stop() noexcept {
    if (!running_.exchange(false)) {
        return;
    }
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

bool BatchAggregator::is_running() const noexcept {
    return running_.load(std::memory_order_relaxed);
}

size_t BatchAggregator::total_batches_dispatched() const noexcept {
    return total_batches_dispatched_.load(std::memory_order_relaxed);
}

size_t BatchAggregator::total_count_triggers() const noexcept {
    return total_count_triggers_.load(std::memory_order_relaxed);
}

size_t BatchAggregator::total_timer_triggers() const noexcept {
    return total_timer_triggers_.load(std::memory_order_relaxed);
}

void BatchAggregator::flush_active_batch(bool is_count_trigger) {
    if (active_batch_.empty()) {
        return;
    }

    IngestionBatch batch_to_dispatch;
    batch_to_dispatch.swap(active_batch_);
    active_batch_.reserve(max_batch_size_);

    while (!output_batch_queue_->push_with_timeout(batch_to_dispatch, std::chrono::milliseconds(100))) {
        if (output_batch_queue_->is_shutdown()) {
            break;
        }
    }

    total_batches_dispatched_.fetch_add(1, std::memory_order_relaxed);
    if (is_count_trigger) {
        total_count_triggers_.fetch_add(1, std::memory_order_relaxed);
    } else {
        total_timer_triggers_.fetch_add(1, std::memory_order_relaxed);
    }
}

void BatchAggregator::aggregator_loop() {
    batch_start_time_ = std::chrono::steady_clock::now();

    while (running_.load(std::memory_order_relaxed)) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - batch_start_time_);

        std::chrono::milliseconds pop_timeout = std::chrono::milliseconds(10);
        if (!active_batch_.empty() && elapsed < max_batch_delay_) {
            pop_timeout = std::min(pop_timeout, max_batch_delay_ - elapsed);
        }

        auto envelope_opt = input_queue_->pop(pop_timeout);
        if (envelope_opt.has_value()) {
            if (active_batch_.empty()) {
                batch_start_time_ = std::chrono::steady_clock::now();
            }
            active_batch_.push_back(std::move(envelope_opt.value()));

            if (active_batch_.size() >= max_batch_size_) {
                flush_active_batch(true);
            }
        }

        if (!active_batch_.empty()) {
            auto current_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - batch_start_time_);
            if (current_elapsed >= max_batch_delay_) {
                flush_active_batch(false);
            }
        }
    }

    // Drain all remaining envelopes in input_queue_ on shutdown
    while (auto envelope_opt = input_queue_->pop(std::chrono::milliseconds(0))) {
        if (active_batch_.empty()) {
            batch_start_time_ = std::chrono::steady_clock::now();
        }
        active_batch_.push_back(std::move(envelope_opt.value()));
        if (active_batch_.size() >= max_batch_size_) {
            flush_active_batch(true);
        }
    }

    // Flush any remaining active batch
    if (!active_batch_.empty()) {
        flush_active_batch(false);
    }
}

} // namespace securecloud::audit::ingestion