#pragma once

#include "audit_config.hpp"
#include "ingestion/batch_aggregator.hpp"
#include "ingestion/bounded_ingestion_queue.hpp"
#include "ingestion/deduplication_interface.hpp"
#include "ingestion/insert_worker_pool.hpp"
#include "ingestion/validation_worker_pool.hpp"
#include "repository/audit_event_repository_interface.hpp"

#include <atomic>
#include <chrono>
#include <memory>

namespace securecloud::audit::ingestion {

/// End-to-end asynchronous audit ingestion pipeline coordinating all processing stages.
class AuditIngestionPipeline {
  public:
    AuditIngestionPipeline(const IngestionConfig& config, std::shared_ptr<repository::IAuditEventRepository> repository,
                           std::shared_ptr<IDeduplicationManager> dedup_manager = nullptr);

    ~AuditIngestionPipeline();

    AuditIngestionPipeline(const AuditIngestionPipeline&) = delete;
    AuditIngestionPipeline& operator=(const AuditIngestionPipeline&) = delete;

    void start();
    void shutdown(std::chrono::milliseconds timeout = std::chrono::milliseconds(5000)) noexcept;

    [[nodiscard]] bool submit(IngestionEnvelope envelope);
    [[nodiscard]] bool is_running() const noexcept;
    [[nodiscard]] bool is_accepting() const noexcept;

    [[nodiscard]] std::shared_ptr<BoundedIngestionQueue> input_queue() const noexcept { return input_queue_; }
    [[nodiscard]] std::shared_ptr<ValidationWorkerPool> validation_pool() const noexcept { return validation_pool_; }
    [[nodiscard]] std::shared_ptr<BatchAggregator> batch_aggregator() const noexcept { return batch_aggregator_; }
    [[nodiscard]] std::shared_ptr<InsertWorkerPool> insert_pool() const noexcept { return insert_pool_; }

  private:
    IngestionConfig config_;
    std::shared_ptr<repository::IAuditEventRepository> repository_;
    std::shared_ptr<IDeduplicationManager> dedup_manager_;

    std::shared_ptr<BoundedIngestionQueue> input_queue_;
    std::shared_ptr<BoundedIngestionQueue> validated_queue_;
    std::shared_ptr<ValidationWorkerPool> validation_pool_;

    std::shared_ptr<BoundedBatchQueue> batch_queue_;
    std::shared_ptr<BatchAggregator> batch_aggregator_;
    std::shared_ptr<InsertWorkerPool> insert_pool_;

    std::atomic<bool> running_{false};
    std::atomic<bool> accepting_{false};
};

} // namespace securecloud::audit::ingestion