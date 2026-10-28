#include "ingestion/validation_worker_pool.hpp"
#include "ingestion/in_memory_deduplication_manager.hpp"
#include "domain/audit_event_validator.hpp"
#include "domain/sensitive_data_guard.hpp"

namespace securecloud::audit::ingestion {

ValidationWorkerPool::ValidationWorkerPool(
    size_t num_workers,
    std::shared_ptr<BoundedIngestionQueue> input_queue,
    std::shared_ptr<BoundedIngestionQueue> output_queue,
    std::shared_ptr<IDeduplicationManager> dedup_manager)
    : num_workers_(num_workers == 0 ? 4 : num_workers),
      input_queue_(std::move(input_queue)),
      output_queue_(std::move(output_queue)),
      dedup_manager_(std::move(dedup_manager)) {
    if (!dedup_manager_) {
        dedup_manager_ = std::make_shared<NoopDeduplicationManager>();
    }
}

ValidationWorkerPool::~ValidationWorkerPool() {
    stop();
}

void ValidationWorkerPool::start() {
    if (running_.exchange(true)) {
        return;
    }

    workers_.reserve(num_workers_);
    for (size_t i = 0; i < num_workers_; ++i) {
        workers_.emplace_back(&ValidationWorkerPool::worker_loop, this);
    }
}

void ValidationWorkerPool::stop() noexcept {
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

bool ValidationWorkerPool::is_running() const noexcept {
    return running_.load(std::memory_order_relaxed);
}

size_t ValidationWorkerPool::total_validated() const noexcept {
    return total_validated_.load(std::memory_order_relaxed);
}

size_t ValidationWorkerPool::total_rejected() const noexcept {
    return total_rejected_.load(std::memory_order_relaxed);
}

size_t ValidationWorkerPool::total_duplicates() const noexcept {
    return total_duplicates_.load(std::memory_order_relaxed);
}

void ValidationWorkerPool::worker_loop() {
    while (running_.load(std::memory_order_relaxed)) {
        auto envelope_opt = input_queue_->pop(std::chrono::milliseconds(50));
        if (!envelope_opt.has_value()) {
            if (input_queue_->is_shutdown()) {
                break;
            }
            continue;
        }

        auto envelope = std::move(envelope_opt.value());

        // 1. Domain schema and temporal bounds validation
        auto val_res = domain::AuditEventValidator::validate(envelope.event);
        if (!val_res.is_valid()) {
            total_rejected_.fetch_add(1, std::memory_order_relaxed);
            service::IngestionResult fail_res{
                .success = false,
                .error_code = "INVALID_ARGUMENT",
                .error_message = val_res.errors().empty() ? "Validation failed" : val_res.errors().front().message,
                .received_at = std::chrono::system_clock::now()
            };

            if (envelope.completion_promise) {
                envelope.completion_promise->set_value(fail_res);
            }
            if (envelope.completion_callback) {
                envelope.completion_callback(fail_res);
            }
            continue;
        }

        // 2. Zero-plaintext sensitive data defense
        auto sensitive_check = domain::SensitiveDataGuard::inspect(envelope.event);
        if (!sensitive_check.is_valid()) {
            total_rejected_.fetch_add(1, std::memory_order_relaxed);
            service::IngestionResult fail_res{
                .success = false,
                .error_code = "INVALID_ARGUMENT",
                .error_message = sensitive_check.errors().empty() ? "Sensitive data policy violation" : sensitive_check.errors().front().message,
                .received_at = std::chrono::system_clock::now()
            };

            if (envelope.completion_promise) {
                envelope.completion_promise->set_value(fail_res);
            }
            if (envelope.completion_callback) {
                envelope.completion_callback(fail_res);
            }
            continue;
        }

        // 3. Assign authoritative server ingestion timestamp
        envelope.event.received_at = std::chrono::system_clock::now();

        // 4. Deduplication hook evaluation
        auto occurred_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                envelope.event.occurred_at.time_since_epoch()).count());

        if (dedup_manager_->is_duplicate(envelope.event.event_id, occurred_ms)) {
            total_duplicates_.fetch_add(1, std::memory_order_relaxed);
            service::IngestionResult dup_res{
                .success = true,
                .error_code = "DUPLICATE_EVENT_IGNORED",
                .error_message = "Event deduplicated",
                .received_at = envelope.event.received_at.value()
            };

            if (envelope.completion_promise) {
                envelope.completion_promise->set_value(dup_res);
            }
            if (envelope.completion_callback) {
                envelope.completion_callback(dup_res);
            }
            continue;
        }

        dedup_manager_->record_processed(envelope.event.event_id, occurred_ms);

        // 5. Enqueue into validated output queue for BatchAggregator
        while (running_.load(std::memory_order_relaxed) &&
               !output_queue_->push_with_timeout(envelope, std::chrono::milliseconds(100))) {
            if (output_queue_->is_shutdown()) {
                break;
            }
        }

        total_validated_.fetch_add(1, std::memory_order_relaxed);
    }
}

} // namespace securecloud::audit::ingestion