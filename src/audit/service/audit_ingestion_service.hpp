#pragma once

#include "domain/audit_event.hpp"
#include "domain/event_payload_fingerprint.hpp"
#include "ingestion/acknowledgement_manager.hpp"
#include "ingestion/deduplication_cache.hpp"
#include "ingestion/idempotency_types.hpp"
#include "repository/audit_event_repository_interface.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace securecloud::audit::service {

struct BatchIngestionResult {
    uint32_t accepted_count{0};
    uint32_t rejected_count{0};
    std::vector<domain::EventId> rejected_event_ids{};
    std::vector<std::pair<domain::EventId, IngestionResult>> item_results{};
};

class AuditIngestionService {
  public:
    explicit AuditIngestionService(std::shared_ptr<repository::IAuditEventRepository> repository,
                                   std::shared_ptr<ingestion::IDeduplicationCache> dedup_cache = nullptr,
                                   std::chrono::milliseconds in_flight_timeout = std::chrono::milliseconds(5000));

    [[nodiscard]] IngestionResult ingest_single(const domain::AuditEvent& event);

    [[nodiscard]] BatchIngestionResult ingest_batch(const std::vector<domain::AuditEvent>& events);

  private:
    std::shared_ptr<repository::IAuditEventRepository> repository_;
    std::shared_ptr<ingestion::IDeduplicationCache> dedup_cache_;
    ingestion::AcknowledgementManager ack_manager_;
    std::chrono::milliseconds in_flight_timeout_{5000};
};

} // namespace securecloud::audit::service