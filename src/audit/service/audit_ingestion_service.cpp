#include "service/audit_ingestion_service.hpp"

namespace securecloud::audit::service {

AuditIngestionService::AuditIngestionService(
    std::shared_ptr<repository::IAuditEventRepository> repository)
    : repository_(std::move(repository)) {}

IngestionResult AuditIngestionService::ingest_single(domain::AuditEvent event) {
    auto now = std::chrono::system_clock::now();
    event.received_at = now;

    auto validation_res = domain::AuditEventValidator::validate(event);
    if (!validation_res.is_valid()) {
        const auto& err = validation_res.errors().front();
        return IngestionResult{
            .success = false,
            .error_code = std::string(to_string(err.code)),
            .error_message = err.message,
            .received_at = now
        };
    }

    if (repository_) {
        repository_->insert_batch({event});
    }

    return IngestionResult{
        .success = true,
        .error_code = "",
        .error_message = "",
        .received_at = now
    };
}

BatchIngestionResult AuditIngestionService::ingest_batch(std::vector<domain::AuditEvent> events) {
    BatchIngestionResult batch_result{};

    if (events.size() > kMaxBatchSize) {
        batch_result.rejected_count = static_cast<uint32_t>(events.size());
        for (const auto& event : events) {
            batch_result.item_results.emplace_back(
                event.event_id,
                IngestionResult{
                    .success = false,
                    .error_code = "BATCH_SIZE_EXCEEDED",
                    .error_message = "Batch size exceeds maximum limit of " + std::to_string(kMaxBatchSize) + " events",
                    .received_at = std::chrono::system_clock::now()
                }
            );
        }
        return batch_result;
    }

    std::vector<domain::AuditEvent> valid_events;
    valid_events.reserve(events.size());

    for (auto& event : events) {
        auto now = std::chrono::system_clock::now();
        event.received_at = now;

        auto validation_res = domain::AuditEventValidator::validate(event);
        if (!validation_res.is_valid()) {
            const auto& err = validation_res.errors().front();
            batch_result.rejected_count++;
            batch_result.item_results.emplace_back(
                event.event_id,
                IngestionResult{
                    .success = false,
                    .error_code = std::string(to_string(err.code)),
                    .error_message = err.message,
                    .received_at = now
                }
            );
        } else {
            batch_result.accepted_count++;
            valid_events.push_back(event);
            batch_result.item_results.emplace_back(
                event.event_id,
                IngestionResult{
                    .success = true,
                    .error_code = "",
                    .error_message = "",
                    .received_at = now
                }
            );
        }
    }

    if (!valid_events.empty() && repository_) {
        repository_->insert_batch(valid_events);
    }

    return batch_result;
}

} // namespace securecloud::audit::service