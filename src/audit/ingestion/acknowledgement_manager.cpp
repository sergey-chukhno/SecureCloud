#include "ingestion/acknowledgement_manager.hpp"

namespace securecloud::audit::ingestion {

void AcknowledgementManager::on_batch_persisted(const std::vector<domain::AuditEvent>& batch,
                                                std::chrono::steady_clock::time_point now) {
    for (const auto& event : batch) {
        auto received_at = event.received_at.value_or(std::chrono::system_clock::now());
        if (dedup_cache_) {
            dedup_cache_->mark_committed(event.event_id, received_at, now);
        }
    }
}

void AcknowledgementManager::on_batch_failed(const std::vector<domain::AuditEvent>& batch,
                                             const repository::RepositoryBatchWriteResult& write_result) {
    IngestionOutcomeStatus outcome_status = IngestionOutcomeStatus::PersistenceFailed;
    if (write_result.status == repository::RepositoryWriteStatus::AmbiguousOutcome) {
        outcome_status = IngestionOutcomeStatus::PersistenceAmbiguous;
    }

    for (const auto& event : batch) {
        PersistAckResult failure_ack{.status = outcome_status,
                                     .event_id = event.event_id,
                                     .received_at = event.received_at.value_or(std::chrono::system_clock::now()),
                                     .error_code = write_result.error_code,
                                     .diagnostic_message = write_result.sanitized_reason};

        if (dedup_cache_) {
            dedup_cache_->rollback_in_flight(event.event_id, failure_ack);
        }
    }
}

void AcknowledgementManager::complete_batch_success(const IngestionBatch& batch) {
    for (const auto& envelope : batch) {
        service::IngestionResult result{.success = true,
                                        .error_code = "",
                                        .error_message = "",
                                        .received_at =
                                            envelope.event.received_at.value_or(std::chrono::system_clock::now())};

        if (envelope.completion_promise) {
            envelope.completion_promise->set_value(result);
        }
        if (envelope.completion_callback) {
            envelope.completion_callback(result);
        }
    }
}

void AcknowledgementManager::complete_batch_failure(const IngestionBatch& batch, const std::string& error_code,
                                                    const std::string& error_message) {
    for (const auto& envelope : batch) {
        service::IngestionResult result{.success = false,
                                        .error_code = error_code,
                                        .error_message = error_message,
                                        .received_at =
                                            envelope.event.received_at.value_or(std::chrono::system_clock::now())};

        if (envelope.completion_promise) {
            envelope.completion_promise->set_value(result);
        }
        if (envelope.completion_callback) {
            envelope.completion_callback(result);
        }
    }
}

} // namespace securecloud::audit::ingestion