#include "ingestion/audit_ingestion_pipeline.hpp"
#include "ingestion/validation_worker_pool.hpp"

namespace securecloud::audit::ingestion {

AuditIngestionPipeline::AuditIngestionPipeline(
    const IngestionConfig& config,
    std::shared_ptr<repository::IAuditEventRepository> repository,
    std::shared_ptr<IDeduplicationCache> dedup_cache)
    : config_(config),
      repository_(std::move(repository)),
      dedup_cache_(std::move(dedup_cache)) {

    input_queue_ = std::make_shared<BoundedIngestionQueue>(config_.max_queued_events);
    validated_queue_ = std::make_shared<BoundedIngestionQueue>(config_.max_queued_events);
    batch_queue_ = std::make_shared<BoundedBatchQueue>(32);

    validation_pool_ = std::make_shared<ValidationWorkerPool>(
        config_.workers, input_queue_, validated_queue_, nullptr);

    batch_aggregator_ = std::make_shared<BatchAggregator>(
        config_.batch_size, std::chrono::milliseconds(config_.batch_flush_interval_ms),
        validated_queue_, batch_queue_);

    insert_pool_ = std::make_shared<InsertWorkerPool>(
        2, batch_queue_, repository_);
}

AuditIngestionPipeline::~AuditIngestionPipeline() {
    shutdown(std::chrono::milliseconds(1000));
}

void AuditIngestionPipeline::start() {
    if (running_.exchange(true)) {
        return;
    }

    insert_pool_->start();
    batch_aggregator_->start();
    validation_pool_->start();

    accepting_.store(true, std::memory_order_relaxed);
}

void AuditIngestionPipeline::shutdown(std::chrono::milliseconds timeout) noexcept {
    (void)timeout;
    if (!running_.exchange(false)) {
        return;
    }

    accepting_.store(false, std::memory_order_relaxed);

    // 1. Stop input queue and drain validation pool
    input_queue_->shutdown();
    validation_pool_->stop();

    // 2. Stop validated queue and drain batch aggregator
    validated_queue_->shutdown();
    batch_aggregator_->stop();

    // 3. Stop batch queue and drain insert pool
    batch_queue_->shutdown();
    insert_pool_->stop();
}

bool AuditIngestionPipeline::submit(IngestionEnvelope envelope) {
    if (!accepting_.load(std::memory_order_relaxed)) {
        return false;
    }
    return input_queue_->try_push(std::move(envelope));
}

bool AuditIngestionPipeline::is_running() const noexcept {
    return running_.load(std::memory_order_relaxed);
}

bool AuditIngestionPipeline::is_accepting() const noexcept {
    return accepting_.load(std::memory_order_relaxed);
}

} // namespace securecloud::audit::ingestion