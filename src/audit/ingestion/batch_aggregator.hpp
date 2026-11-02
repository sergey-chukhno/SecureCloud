#pragma once

#include "ingestion/bounded_ingestion_queue.hpp"
#include "ingestion/ingestion_envelope.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

namespace securecloud::audit::ingestion {

using IngestionBatch = std::vector<IngestionEnvelope>;

/// Thread-safe bounded queue for holding aggregated event batches.
class BoundedBatchQueue {
  public:
    explicit BoundedBatchQueue(size_t capacity = 32);
    ~BoundedBatchQueue();

    BoundedBatchQueue(const BoundedBatchQueue&) = delete;
    BoundedBatchQueue& operator=(const BoundedBatchQueue&) = delete;

    [[nodiscard]] bool try_push(IngestionBatch batch);
    [[nodiscard]] bool push_with_timeout(IngestionBatch batch, std::chrono::milliseconds timeout);
    [[nodiscard]] std::optional<IngestionBatch> pop(std::chrono::milliseconds timeout);

    [[nodiscard]] size_t size() const noexcept;
    [[nodiscard]] size_t capacity() const noexcept;
    [[nodiscard]] bool is_shutdown() const noexcept;
    void shutdown() noexcept;

  private:
    const size_t capacity_;
    mutable std::mutex mutex_;
    std::condition_variable cv_not_full_;
    std::condition_variable cv_not_empty_;
    std::deque<IngestionBatch> queue_;
    bool shutdown_{false};
};

/// Aggregates validated events into contiguous batches using count (1,000) or time (100 ms) dual triggers.
class BatchAggregator {
  public:
    BatchAggregator(size_t max_batch_size, std::chrono::milliseconds max_batch_delay,
                    std::shared_ptr<BoundedIngestionQueue> input_queue,
                    std::shared_ptr<BoundedBatchQueue> output_batch_queue);

    ~BatchAggregator();

    BatchAggregator(const BatchAggregator&) = delete;
    BatchAggregator& operator=(const BatchAggregator&) = delete;

    void start();
    void stop() noexcept;

    [[nodiscard]] bool is_running() const noexcept;
    [[nodiscard]] size_t total_batches_dispatched() const noexcept;
    [[nodiscard]] size_t total_count_triggers() const noexcept;
    [[nodiscard]] size_t total_timer_triggers() const noexcept;

  private:
    void aggregator_loop();
    void flush_active_batch(bool is_count_trigger);

    const size_t max_batch_size_;
    const std::chrono::milliseconds max_batch_delay_;
    std::shared_ptr<BoundedIngestionQueue> input_queue_;
    std::shared_ptr<BoundedBatchQueue> output_batch_queue_;

    std::atomic<bool> running_{false};
    std::thread worker_thread_;

    IngestionBatch active_batch_;
    std::chrono::steady_clock::time_point batch_start_time_;

    std::atomic<size_t> total_batches_dispatched_{0};
    std::atomic<size_t> total_count_triggers_{0};
    std::atomic<size_t> total_timer_triggers_{0};
};

} // namespace securecloud::audit::ingestion