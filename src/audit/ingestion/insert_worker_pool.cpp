#include "ingestion/insert_worker_pool.hpp"

#include "ingestion/acknowledgement_manager.hpp"
#include "repository/clickhouse_client.hpp"
#include "telemetry/audit_metrics.hpp"

namespace securecloud::audit::ingestion {

InsertWorkerPool::InsertWorkerPool(size_t num_workers, std::shared_ptr<BoundedBatchQueue> input_batch_queue,
                                   std::shared_ptr<repository::IAuditEventRepository> repository,
                                   std::shared_ptr<IDeduplicationCache> dedup_cache)
    : num_workers_(num_workers == 0 ? 2 : num_workers), input_batch_queue_(std::move(input_batch_queue)),
      repository_(std::move(repository)), acknowledgement_manager_(std::move(dedup_cache)) {}

InsertWorkerPool::~InsertWorkerPool() {
    stop();
}

void InsertWorkerPool::start() {
    if (running_.exchange(true)) {
        return;
    }

    workers_.reserve(num_workers_);
    telemetry::AuditMetrics::instance().set_active_workers(telemetry::WorkerPoolLabel::Insertion,
                                                           static_cast<int64_t>(num_workers_));
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
    telemetry::AuditMetrics::instance().set_active_workers(telemetry::WorkerPoolLabel::Insertion, 0);
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
    auto fail_batch = [this](const IngestionBatch& batch, const std::vector<domain::AuditEvent>& events,
                             repository::RepositoryWriteStatus status, std::string error_code, std::string reason) {
        acknowledgement_manager_.on_batch_failed(
            events, repository::RepositoryBatchWriteResult{
                        .status = status, .error_code = error_code, .sanitized_reason = reason});
        const auto outcome = status == repository::RepositoryWriteStatus::AmbiguousOutcome
                                 ? IngestionOutcomeStatus::PersistenceAmbiguous
                                 : IngestionOutcomeStatus::PersistenceFailed;
        AcknowledgementManager::complete_batch_failure(batch, error_code, reason, outcome);
        total_failed_batches_.fetch_add(1, std::memory_order_relaxed);
        total_failed_events_.fetch_add(events.size(), std::memory_order_relaxed);
    };

    auto process_batch = [this, &fail_batch](IngestionBatch batch) {
        if (batch.empty()) {
            return;
        }

        std::vector<domain::AuditEvent> events;
        events.reserve(batch.size());
        for (const auto& envelope : batch) {
            events.push_back(envelope.event);
        }

        try {
            const auto write_result = repository_->insert_batch_classified(events);
            if (write_result.status == repository::RepositoryWriteStatus::Committed) {
                acknowledgement_manager_.on_batch_persisted(events);
                total_inserted_batches_.fetch_add(1, std::memory_order_relaxed);
                total_inserted_events_.fetch_add(events.size(), std::memory_order_relaxed);

                AcknowledgementManager::complete_batch_success(batch);
            } else {
                const bool ambiguous = write_result.status == repository::RepositoryWriteStatus::AmbiguousOutcome;
                fail_batch(batch, events, write_result.status,
                           write_result.error_code.empty() ? (ambiguous ? "DEADLINE_EXCEEDED" : "UNAVAILABLE")
                                                           : write_result.error_code,
                           write_result.sanitized_reason.empty() ? "ClickHouse batch persistence failed"
                                                                 : write_result.sanitized_reason);
            }
        } catch (const repository::ClickHouseTimeoutException& ex) {
            (void)ex;
            fail_batch(batch, events, repository::RepositoryWriteStatus::AmbiguousOutcome, "DEADLINE_EXCEEDED",
                       "ClickHouse batch insertion query timed out");
        } catch (const repository::ClickHouseConnectionException& ex) {
            (void)ex;
            fail_batch(batch, events, repository::RepositoryWriteStatus::DeterministicFailure, "UNAVAILABLE",
                       "ClickHouse analytical cluster connectivity failure");
        } catch (const std::exception& ex) {
            std::string msg = ex.what();
            if (msg.find("timeout") != std::string::npos || msg.find("timed out") != std::string::npos) {
                fail_batch(batch, events, repository::RepositoryWriteStatus::AmbiguousOutcome, "DEADLINE_EXCEEDED",
                           "ClickHouse batch insertion query timed out");
            } else {
                fail_batch(batch, events, repository::RepositoryWriteStatus::DeterministicFailure, "UNAVAILABLE",
                           "ClickHouse batch persistence failed");
            }
        }
    };

    while (running_.load(std::memory_order_relaxed)) {
        auto batch_opt = input_batch_queue_->pop(std::chrono::milliseconds(50));
        if (!batch_opt.has_value()) {
            if (input_batch_queue_->is_shutdown()) {
                break;
            }
            continue;
        }

        process_batch(std::move(batch_opt.value()));
    }

    // Drain remaining batches in input_batch_queue_ on shutdown
    while (auto batch_opt = input_batch_queue_->pop(std::chrono::milliseconds(0))) {
        process_batch(std::move(batch_opt.value()));
    }
}

} // namespace securecloud::audit::ingestion
