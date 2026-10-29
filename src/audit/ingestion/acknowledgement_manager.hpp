#pragma once

#include "domain/audit_event.hpp"
#include "ingestion/batch_aggregator.hpp"
#include "ingestion/deduplication_cache.hpp"
#include "ingestion/idempotency_types.hpp"
#include "repository/audit_event_repository_interface.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace securecloud::audit::ingestion {

/// Exception-safe RAII guard ensuring IN_FLIGHT cache entries are automatically
/// rolled back if an event fails to enter the pipeline or is discarded before batching.
class InFlightReservationGuard {
  public:
    InFlightReservationGuard(std::shared_ptr<IDeduplicationCache> cache,
                             domain::EventId event_id,
                             PersistAckResult default_failure_ack)
        : cache_(std::move(cache)),
          event_id_(event_id),
          failure_ack_(std::move(default_failure_ack)),
          dismissed_(false) {}

    ~InFlightReservationGuard() {
        if (!dismissed_ && cache_) {
            cache_->rollback_in_flight(event_id_, failure_ack_);
        }
    }

    InFlightReservationGuard(const InFlightReservationGuard&) = delete;
    InFlightReservationGuard& operator=(const InFlightReservationGuard&) = delete;

    InFlightReservationGuard(InFlightReservationGuard&& other) noexcept
        : cache_(std::move(other.cache_)),
          event_id_(other.event_id_),
          failure_ack_(std::move(other.failure_ack_)),
          dismissed_(other.dismissed_) {
        other.dismissed_ = true;
    }

    InFlightReservationGuard& operator=(InFlightReservationGuard&& other) noexcept {
        if (this != &other) {
            if (!dismissed_ && cache_) {
                cache_->rollback_in_flight(event_id_, failure_ack_);
            }
            cache_ = std::move(other.cache_);
            event_id_ = other.event_id_;
            failure_ack_ = std::move(other.failure_ack_);
            dismissed_ = other.dismissed_;
            other.dismissed_ = true;
        }
        return *this;
    }

    /// Dismisses the guard when the event is successfully handed off to the batch pipeline.
    void dismiss() noexcept { dismissed_ = true; }

  private:
    std::shared_ptr<IDeduplicationCache> cache_;
    domain::EventId event_id_;
    PersistAckResult failure_ack_;
    bool dismissed_{false};
};

/// Manages the resolution of durability guarantees (promises and callbacks) for ingested event batches
/// and coordinates cache state transitions with BoundedDeduplicationCache.
class AcknowledgementManager {
  public:
    explicit AcknowledgementManager(std::shared_ptr<IDeduplicationCache> dedup_cache = nullptr)
        : dedup_cache_(std::move(dedup_cache)) {}

    /// Marks all events in the batch as COMMITTED in the deduplication cache and completes
    /// primary caller promises with success.
    void on_batch_persisted(
        const std::vector<domain::AuditEvent>& batch,
        std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    /// Rolls back all IN_FLIGHT events in the batch to UNSEEN in the deduplication cache
    /// and fulfills caller promises with classified failure results.
    void on_batch_failed(
        const std::vector<domain::AuditEvent>& batch,
        const repository::RepositoryBatchWriteResult& write_result);

    /// Completes all promises and callbacks in the batch with affirmative success status (IngestionBatch overload).
    static void complete_batch_success(const IngestionBatch& batch);

    /// Completes all promises and callbacks in the batch with failure details (IngestionBatch overload).
    static void complete_batch_failure(const IngestionBatch& batch, const std::string& error_code,
                                       const std::string& error_message);

    /// Sets or updates the deduplication cache dependency.
    void set_deduplication_cache(std::shared_ptr<IDeduplicationCache> cache) noexcept {
        dedup_cache_ = std::move(cache);
    }

  private:
    std::shared_ptr<IDeduplicationCache> dedup_cache_;
};

} // namespace securecloud::audit::ingestion