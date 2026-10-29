#include "service/audit_ingestion_service.hpp"

#include "domain/audit_event_validator.hpp"

namespace securecloud::audit::service {

AuditIngestionService::AuditIngestionService(std::shared_ptr<repository::IAuditEventRepository> repository,
                                             std::shared_ptr<ingestion::IDeduplicationCache> dedup_cache,
                                             std::chrono::milliseconds in_flight_timeout)
    : repository_(std::move(repository)), dedup_cache_(std::move(dedup_cache)), ack_manager_(dedup_cache_),
      in_flight_timeout_(in_flight_timeout) {}

IngestionResult AuditIngestionService::ingest_single(const domain::AuditEvent& event) {
    auto val_result = domain::AuditEventValidator::validate(event);
    if (!val_result.is_valid()) {
        return IngestionResult{.success = false,
                               .outcome_status = ingestion::IngestionOutcomeStatus::ValidationRejected,
                               .error_code = "INVALID_ARGUMENT",
                               .error_message = val_result.errors().empty() ? "Validation failed"
                                                                            : val_result.errors().front().message,
                               .received_at = std::chrono::system_clock::now()};
    }

    auto now_steady = std::chrono::steady_clock::now();
    auto received_at = event.received_at.value_or(std::chrono::system_clock::now());

    if (dedup_cache_) {
        auto fp = domain::EventPayloadFingerprint::compute(event);
        auto acq = dedup_cache_->try_acquire(event.event_id, fp, now_steady);

        switch (acq.decision) {
        case ingestion::DedupAcquireResult::Decision::AlreadyCommitted:
            return IngestionResult{.success = true,
                                   .outcome_status = ingestion::IngestionOutcomeStatus::DuplicateCommitted,
                                   .error_code = "",
                                   .error_message = "",
                                   .received_at = acq.committed_received_at};

        case ingestion::DedupAcquireResult::Decision::PayloadConflict:
            return IngestionResult{.success = false,
                                   .outcome_status = ingestion::IngestionOutcomeStatus::IdempotencyConflict,
                                   .error_code = "ALREADY_EXISTS",
                                   .error_message =
                                       "Idempotency conflict: event_id already exists with different payload",
                                   .received_at = received_at};

        case ingestion::DedupAcquireResult::Decision::CoalescedInFlight:
            if (acq.in_flight_future.valid()) {
                if (acq.in_flight_future.wait_for(in_flight_timeout_) == std::future_status::ready) {
                    auto ack = acq.in_flight_future.get();
                    bool ok = (ack.status == ingestion::IngestionOutcomeStatus::PersistedNew ||
                               ack.status == ingestion::IngestionOutcomeStatus::DuplicateCoalesced);
                    return IngestionResult{.success = ok,
                                           .outcome_status =
                                               ok ? ingestion::IngestionOutcomeStatus::DuplicateCoalesced : ack.status,
                                           .error_code = ack.error_code,
                                           .error_message = ack.diagnostic_message,
                                           .received_at = ack.received_at};
                } else {
                    return IngestionResult{.success = false,
                                           .outcome_status = ingestion::IngestionOutcomeStatus::PersistenceAmbiguous,
                                           .error_code = "DEADLINE_EXCEEDED",
                                           .error_message = "In-flight persistence acknowledgment timed out",
                                           .received_at = received_at};
                }
            }
            break;

        case ingestion::DedupAcquireResult::Decision::AcquiredNewInFlight: {
            ingestion::PersistAckResult default_failure{.status = ingestion::IngestionOutcomeStatus::PersistenceFailed,
                                                        .event_id = event.event_id,
                                                        .received_at = received_at,
                                                        .error_code = "REPOSITORY_ERROR",
                                                        .diagnostic_message =
                                                            "ClickHouse batch persistence insertion failed"};
            ingestion::InFlightReservationGuard guard(dedup_cache_, event.event_id, default_failure);

            domain::AuditEvent event_to_insert = event;
            event_to_insert.received_at = received_at;

            auto write_res = repository_->insert_batch_classified({event_to_insert});
            guard.dismiss();

            if (write_res.status == repository::RepositoryWriteStatus::Committed) {
                ack_manager_.on_batch_persisted({event_to_insert}, now_steady);
                return IngestionResult{.success = true,
                                       .outcome_status = ingestion::IngestionOutcomeStatus::PersistedNew,
                                       .error_code = "",
                                       .error_message = "",
                                       .received_at = received_at};
            } else {
                ack_manager_.on_batch_failed({event_to_insert}, write_res);
                auto outcome = (write_res.status == repository::RepositoryWriteStatus::AmbiguousOutcome)
                                   ? ingestion::IngestionOutcomeStatus::PersistenceAmbiguous
                                   : ingestion::IngestionOutcomeStatus::PersistenceFailed;
                return IngestionResult{.success = false,
                                       .outcome_status = outcome,
                                       .error_code = write_res.error_code,
                                       .error_message = write_res.sanitized_reason,
                                       .received_at = received_at};
            }
        }
        }
    }

    // Direct insertion fallback if deduplication cache is disabled
    try {
        domain::AuditEvent event_to_insert = event;
        event_to_insert.received_at = received_at;
        auto write_res = repository_->insert_batch_classified({event_to_insert});
        if (write_res.status == repository::RepositoryWriteStatus::Committed) {
            return IngestionResult{.success = true,
                                   .outcome_status = ingestion::IngestionOutcomeStatus::PersistedNew,
                                   .error_code = "",
                                   .error_message = "",
                                   .received_at = received_at};
        }
        auto outcome = (write_res.status == repository::RepositoryWriteStatus::AmbiguousOutcome)
                           ? ingestion::IngestionOutcomeStatus::PersistenceAmbiguous
                           : ingestion::IngestionOutcomeStatus::PersistenceFailed;
        return IngestionResult{.success = false,
                               .outcome_status = outcome,
                               .error_code = write_res.error_code,
                               .error_message = write_res.sanitized_reason,
                               .received_at = received_at};
    } catch (const std::exception& ex) {
        return IngestionResult{.success = false,
                               .outcome_status = ingestion::IngestionOutcomeStatus::PersistenceFailed,
                               .error_code = "REPOSITORY_ERROR",
                               .error_message = ex.what(),
                               .received_at = received_at};
    }
}

BatchIngestionResult AuditIngestionService::ingest_batch(const std::vector<domain::AuditEvent>& events) {
    BatchIngestionResult result{};
    if (events.empty()) {
        return result;
    }

    if (events.size() > 100) {
        result.accepted_count = 0;
        result.rejected_count = static_cast<uint32_t>(events.size());
        for (const auto& evt : events) {
            result.rejected_event_ids.push_back(evt.event_id);
            result.item_results.emplace_back(
                evt.event_id, IngestionResult{.success = false,
                                              .outcome_status = ingestion::IngestionOutcomeStatus::ValidationRejected,
                                              .error_code = "INVALID_ARGUMENT",
                                              .error_message = "Batch size exceeds maximum limit of 100 events",
                                              .received_at = std::chrono::system_clock::now()});
        }
        return result;
    }

    auto now_steady = std::chrono::steady_clock::now();
    std::vector<domain::AuditEvent> events_to_insert;
    events_to_insert.reserve(events.size());

    struct CoalescedWaitItem {
        domain::EventId event_id;
        std::shared_future<ingestion::PersistAckResult> future;
    };
    std::vector<CoalescedWaitItem> coalesced_waiters;

    for (const auto& evt : events) {
        auto val_res = domain::AuditEventValidator::validate(evt);
        if (!val_res.is_valid()) {
            result.rejected_count++;
            result.rejected_event_ids.push_back(evt.event_id);
            result.item_results.emplace_back(
                evt.event_id,
                IngestionResult{.success = false,
                                .outcome_status = ingestion::IngestionOutcomeStatus::ValidationRejected,
                                .error_code = "INVALID_ARGUMENT",
                                .error_message =
                                    val_res.errors().empty() ? "Validation failed" : val_res.errors().front().message,
                                .received_at = std::chrono::system_clock::now()});
            continue;
        }

        auto received_at = evt.received_at.value_or(std::chrono::system_clock::now());
        domain::AuditEvent prepared_event = evt;
        prepared_event.received_at = received_at;

        if (dedup_cache_) {
            auto fp = domain::EventPayloadFingerprint::compute(prepared_event);
            auto acq = dedup_cache_->try_acquire(prepared_event.event_id, fp, now_steady);

            switch (acq.decision) {
            case ingestion::DedupAcquireResult::Decision::AlreadyCommitted:
                result.accepted_count++;
                result.item_results.emplace_back(
                    prepared_event.event_id,
                    IngestionResult{.success = true,
                                    .outcome_status = ingestion::IngestionOutcomeStatus::DuplicateCommitted,
                                    .error_code = "",
                                    .error_message = "",
                                    .received_at = acq.committed_received_at});
                continue;

            case ingestion::DedupAcquireResult::Decision::PayloadConflict:
                result.rejected_count++;
                result.rejected_event_ids.push_back(prepared_event.event_id);
                result.item_results.emplace_back(
                    prepared_event.event_id,
                    IngestionResult{.success = false,
                                    .outcome_status = ingestion::IngestionOutcomeStatus::IdempotencyConflict,
                                    .error_code = "ALREADY_EXISTS",
                                    .error_message =
                                        "Idempotency conflict: event_id already exists with different payload",
                                    .received_at = received_at});
                continue;

            case ingestion::DedupAcquireResult::Decision::CoalescedInFlight:
                coalesced_waiters.push_back(
                    CoalescedWaitItem{.event_id = prepared_event.event_id, .future = acq.in_flight_future});
                continue;

            case ingestion::DedupAcquireResult::Decision::AcquiredNewInFlight:
                events_to_insert.push_back(prepared_event);
                continue;
            }
        } else {
            events_to_insert.push_back(prepared_event);
        }
    }

    // Insert acquired items into ClickHouse
    if (!events_to_insert.empty()) {
        auto write_res = repository_->insert_batch_classified(events_to_insert);
        if (write_res.status == repository::RepositoryWriteStatus::Committed) {
            ack_manager_.on_batch_persisted(events_to_insert, now_steady);
            result.accepted_count += static_cast<uint32_t>(events_to_insert.size());
            for (const auto& evt : events_to_insert) {
                result.item_results.emplace_back(
                    evt.event_id,
                    IngestionResult{.success = true,
                                    .outcome_status = ingestion::IngestionOutcomeStatus::PersistedNew,
                                    .error_code = "",
                                    .error_message = "",
                                    .received_at = evt.received_at.value_or(std::chrono::system_clock::now())});
            }
        } else {
            ack_manager_.on_batch_failed(events_to_insert, write_res);
            result.rejected_count += static_cast<uint32_t>(events_to_insert.size());
            auto outcome = (write_res.status == repository::RepositoryWriteStatus::AmbiguousOutcome)
                               ? ingestion::IngestionOutcomeStatus::PersistenceAmbiguous
                               : ingestion::IngestionOutcomeStatus::PersistenceFailed;

            for (const auto& evt : events_to_insert) {
                result.rejected_event_ids.push_back(evt.event_id);
                result.item_results.emplace_back(
                    evt.event_id,
                    IngestionResult{.success = false,
                                    .outcome_status = outcome,
                                    .error_code = write_res.error_code,
                                    .error_message = write_res.sanitized_reason,
                                    .received_at = evt.received_at.value_or(std::chrono::system_clock::now())});
            }
        }
    }

    // Await coalesced futures
    for (auto& wait_item : coalesced_waiters) {
        if (wait_item.future.valid() && wait_item.future.wait_for(in_flight_timeout_) == std::future_status::ready) {
            auto ack = wait_item.future.get();
            bool ok = (ack.status == ingestion::IngestionOutcomeStatus::PersistedNew ||
                       ack.status == ingestion::IngestionOutcomeStatus::DuplicateCoalesced);
            if (ok) {
                result.accepted_count++;
                result.item_results.emplace_back(
                    wait_item.event_id,
                    IngestionResult{.success = true,
                                    .outcome_status = ingestion::IngestionOutcomeStatus::DuplicateCoalesced,
                                    .error_code = "",
                                    .error_message = "",
                                    .received_at = ack.received_at});
            } else {
                result.rejected_count++;
                result.rejected_event_ids.push_back(wait_item.event_id);
                result.item_results.emplace_back(wait_item.event_id,
                                                 IngestionResult{.success = false,
                                                                 .outcome_status = ack.status,
                                                                 .error_code = ack.error_code,
                                                                 .error_message = ack.diagnostic_message,
                                                                 .received_at = ack.received_at});
            }
        } else {
            result.rejected_count++;
            result.rejected_event_ids.push_back(wait_item.event_id);
            result.item_results.emplace_back(
                wait_item.event_id,
                IngestionResult{.success = false,
                                .outcome_status = ingestion::IngestionOutcomeStatus::PersistenceAmbiguous,
                                .error_code = "DEADLINE_EXCEEDED",
                                .error_message = "In-flight persistence acknowledgment timed out",
                                .received_at = std::chrono::system_clock::now()});
        }
    }

    return result;
}

} // namespace securecloud::audit::service