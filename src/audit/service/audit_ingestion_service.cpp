#include "service/audit_ingestion_service.hpp"

#include "domain/audit_event_validator.hpp"

namespace securecloud::audit::service {

AuditIngestionService::AuditIngestionService(std::shared_ptr<repository::IAuditEventRepository> repository)
    : repository_(std::move(repository)) {}

IngestionResult AuditIngestionService::ingest_single(const domain::AuditEvent& event) {
    auto val_result = domain::AuditEventValidator::validate(event);
    if (!val_result.is_valid()) {
        return IngestionResult{.success = false,
                               .error_code = "INVALID_ARGUMENT",
                               .error_message = val_result.errors().empty() ? "Validation failed"
                                                                            : val_result.errors().front().message,
                               .received_at = std::chrono::system_clock::now()};
    }

    try {
        bool ok = repository_->insert_batch({event});
        if (!ok) {
            return IngestionResult{.success = false,
                                   .error_code = "REPOSITORY_ERROR",
                                   .error_message = "ClickHouse persistence insertion failed",
                                   .received_at = std::chrono::system_clock::now()};
        }
    } catch (const std::exception& ex) {
        return IngestionResult{.success = false,
                               .error_code = "REPOSITORY_ERROR",
                               .error_message = ex.what(),
                               .received_at = std::chrono::system_clock::now()};
    }

    return IngestionResult{
        .success = true, .error_code = "", .error_message = "", .received_at = std::chrono::system_clock::now()};
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
            result.item_results.emplace_back(
                evt.event_id, IngestionResult{.success = false,
                                              .error_code = "BATCH_SIZE_EXCEEDED",
                                              .error_message = "Batch size exceeds maximum limit of 100 events",
                                              .received_at = std::chrono::system_clock::now()});
        }
        return result;
    }

    std::vector<domain::AuditEvent> valid_events;
    valid_events.reserve(events.size());

    for (const auto& evt : events) {
        auto val_res = domain::AuditEventValidator::validate(evt);
        if (!val_res.is_valid()) {
            result.rejected_count++;
            result.item_results.emplace_back(evt.event_id,
                                             IngestionResult{.success = false,
                                                             .error_code = "INVALID_ARGUMENT",
                                                             .error_message = val_res.errors().empty()
                                                                                  ? "Validation failed"
                                                                                  : val_res.errors().front().message,
                                                             .received_at = std::chrono::system_clock::now()});
        } else {
            valid_events.push_back(evt);
        }
    }

    if (valid_events.empty()) {
        return result;
    }

    try {
        bool ok = repository_->insert_batch(valid_events);
        if (!ok) {
            for (const auto& evt : valid_events) {
                result.rejected_count++;
                result.item_results.emplace_back(
                    evt.event_id, IngestionResult{.success = false,
                                                  .error_code = "REPOSITORY_ERROR",
                                                  .error_message = "ClickHouse batch persistence insertion failed",
                                                  .received_at = std::chrono::system_clock::now()});
            }
            return result;
        }
    } catch (const std::exception& ex) {
        for (const auto& evt : valid_events) {
            result.rejected_count++;
            result.item_results.emplace_back(evt.event_id,
                                             IngestionResult{.success = false,
                                                             .error_code = "REPOSITORY_ERROR",
                                                             .error_message = ex.what(),
                                                             .received_at = std::chrono::system_clock::now()});
        }
        return result;
    }

    result.accepted_count = static_cast<uint32_t>(valid_events.size());
    for (const auto& evt : valid_events) {
        result.item_results.emplace_back(evt.event_id,
                                         IngestionResult{.success = true,
                                                         .error_code = "",
                                                         .error_message = "",
                                                         .received_at = std::chrono::system_clock::now()});
    }

    return result;
}

} // namespace securecloud::audit::service