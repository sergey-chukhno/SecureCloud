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

class InFlightReservationGuard {
  public:
    InFlightReservationGuard(std::shared_ptr<IDeduplicationCache> cache, domain::EventId event_id,
                             PersistAckResult default_failure_ack)
        : cache_(std::move(cache)), event_id_(event_id), failure_ack_(std::move(default_failure_ack)),
          dismissed_(false) {}

    ~InFlightReservationGuard() {
        if (!dismissed_ && cache_) {
            cache_->rollback_in_flight(event_id_, failure_ack_);
        }
    }

    InFlightReservationGuard(const InFlightReservationGuard&) = delete;
    InFlightReservationGuard& operator=(const InFlightReservationGuard&) = delete;

    InFlightReservationGuard(InFlightReservationGuard&& other) noexcept
        : cache_(std::move(other.cache_)), event_id_(other.event_id_), failure_ack_(std::move(other.failure_ack_)),
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

    void dismiss() noexcept { dismissed_ = true; }

  private:
    std::shared_ptr<IDeduplicationCache> cache_;
    domain::EventId event_id_;
    PersistAckResult failure_ack_;
    bool dismissed_{false};
};

class AcknowledgementManager {
  public:
    explicit AcknowledgementManager(std::shared_ptr<IDeduplicationCache> dedup_cache = nullptr)
        : dedup_cache_(std::move(dedup_cache)) {}

    void on_batch_persisted(const std::vector<domain::AuditEvent>& batch,
                            std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    void on_batch_failed(const std::vector<domain::AuditEvent>& batch,
                         const repository::RepositoryBatchWriteResult& write_result);

    static void complete_batch_success(const IngestionBatch& batch);

    static void complete_batch_failure(const IngestionBatch& batch, const std::string& error_code,
                                       const std::string& error_message);

    void set_deduplication_cache(std::shared_ptr<IDeduplicationCache> cache) noexcept {
        dedup_cache_ = std::move(cache);
    }

  private:
    std::shared_ptr<IDeduplicationCache> dedup_cache_;
};

} // namespace securecloud::audit::ingestion