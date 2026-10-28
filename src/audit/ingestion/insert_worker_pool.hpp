#pragma once

#include "ingestion/batch_aggregator.hpp"
#include "repository/audit_repository_exceptions.hpp"
#include "repository/clickhouse_audit_event_repository.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>
#include <vector>

namespace securecloud::audit::ingestion {

/// Multithreaded worker pool (2 default workers) executing bulk persistence against ClickHouse.
class InsertWorkerPool {
  public:
    InsertWorkerPool(size_t num_workers, std::shared_ptr<BoundedBatchQueue> input_batch_queue,
                     std::shared_ptr<repository::IAuditEventRepository> repository);

    ~InsertWorkerPool();

    InsertWorkerPool(const InsertWorkerPool&) = delete;
    InsertWorkerPool& operator=(const InsertWorkerPool&) = delete;

    void start();
    void stop() noexcept;

    [[nodiscard]] bool is_running() const noexcept;
    [[nodiscard]] size_t total_inserted_batches() const noexcept;
    [[nodiscard]] size_t total_inserted_events() const noexcept;
    [[nodiscard]] size_t total_failed_batches() const noexcept;
    [[nodiscard]] size_t total_failed_events() const noexcept;

  private:
    void worker_loop();

    const size_t num_workers_;
    std::shared_ptr<BoundedBatchQueue> input_batch_queue_;
    std::shared_ptr<repository::IAuditEventRepository> repository_;

    std::atomic<bool> running_{false};
    std::vector<std::thread> workers_;

    std::atomic<size_t> total_inserted_batches_{0};
    std::atomic<size_t> total_inserted_events_{0};
    std::atomic<size_t> total_failed_batches_{0};
    std::atomic<size_t> total_failed_events_{0};
};

} // namespace securecloud::audit::ingestion