#include "ingestion/insert_worker_pool.hpp"
#include "ingestion/acknowledgement_manager.hpp"
#include "repository/clickhouse_client.hpp"

namespace securecloud::audit::ingestion {

InsertWorkerPool::InsertWorkerPool(
    size_t num_workers,
    std::shared_ptr<BoundedBatchQueue> input_batch_queue,
    std::shared_ptr<repository::IAuditEventRepository> repository)
    : num_workers_(num_workers == 0 ? 2 : num_workers),
      input_batch_queue_(std::move(input_batch_queue)),
      repository_(std::move(repository)) {}

InsertWorkerPool::~InsertWorkerPool() {
    stop();
}

void InsertWorkerPool::start() {
    if (running_.exchange(true)) {
        return;
    }

    workers_.reserve(num_workers_);
    for (size_t i = 0; i < num_workers_; ++i) {
        workers_.emplace_back(&InsertWorkerPool::worker_loop, this);
    }
}

void InsertWorkerPool::stop() noexcept {
    if (!running_.exchange(false)) {
        return;
    }

    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    workers_.clear();
}

bool InsertWorkerPool::is_running() const noexcept {
    return running_.load(std::memory_order_relaxed);
}

size_t InsertWorkerPool::total_inserted_batches() const noexcept {
    return total_inserted_batches_.load(std::memory_order_relaxed);
}

size_t InsertWorkerPool::total_inserted_events() const noexcept {
    return total_inserted_events_.load(std::memory_order_relaxed);
}

size_t InsertWorkerPool::total_failed_batches() const noexcept {
    return total_failed_batches_.load(std::memory_order_relaxed);
}

size_t InsertWorkerPool::total_failed_events() const noexcept {
    return total_failed_events_.load(std::memory_order_relaxed);
}

void InsertWorkerPool::worker_loop() {
    while (running_.load(std::memory_order_relaxed)) {
        auto batch_opt = input_batch_queue_->pop(std::chrono::milliseconds(50));
        if (!batch_opt.has_value()) {
            if (input_batch_queue_->is_shutdown()) {
                break;
            }
            continue;
        }

        auto batch = std::move(batch_opt.value());
        if (batch.empty()) {
            continue;
        }

        std::vector<domain::AuditEvent> events;
        events.reserve(batch.size());
        for (const auto& envelope : batch) {
            events.push_back(envelope.event);
        }

        try {
            repository_->insert_batch(events);

            total_inserted_batches_.fetch_add(1, std::memory_order_relaxed);
            total_inserted_events_.fetch_add(events.size(), std::memory_order_relaxed);

            AcknowledgementManager::complete_batch_success(batch);
        } catch (const repository::ClickHouseTimeoutException& ex) {
            (void)ex;
            total_failed_batches_.fetch_add(1, std::memory_order_relaxed);
            total_failed_events_.fetch_add(events.size(), std::memory_order_relaxed);

            AcknowledgementManager::complete_batch_failure(
                batch, "DEADLINE_EXCEEDED", "ClickHouse batch insertion query timed out");
        } catch (const repository::ClickHouseConnectionException& ex) {
            (void)ex;
            total_failed_batches_.fetch_add(1, std::memory_order_relaxed);
            total_failed_events_.fetch_add(events.size(), std::memory_order_relaxed);

            AcknowledgementManager::complete_batch_failure(
                batch, "UNAVAILABLE", "ClickHouse analytical cluster connectivity failure");
        } catch (const std::exception& ex) {
            total_failed_batches_.fetch_add(1, std::memory_order_relaxed);
            total_failed_events_.fetch_add(events.size(), std::memory_order_relaxed);

            std::string msg = ex.what();
            if (msg.find("timeout") != std::string::npos || msg.find("timed out") != std::string::npos) {
                AcknowledgementManager::complete_batch_failure(
                    batch, "DEADLINE_EXCEEDED", "ClickHouse batch insertion query timed out");
            } else {
                AcknowledgementManager::complete_batch_failure(
                    batch, "UNAVAILABLE", "ClickHouse batch persistence failed");
            }
        }
    }
}

} // namespace securecloud::audit::ingestion