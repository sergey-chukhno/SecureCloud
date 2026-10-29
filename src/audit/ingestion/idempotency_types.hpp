#pragma once

#include "domain/event_id.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace securecloud::audit::ingestion {

    enum class DedupState : uint8_t {
        Unseen = 0,
        InFlight = 1,
        Committed = 2
    };

    enum class IngestionOutcomeStatus : uint8_t {
        PersistedNew = 0,        // Durably inserted into ClickHouse on this attempt
        DuplicateCommitted = 1,  // Already durably committed in ClickHouse; idempotent ACK
        DuplicateCoalesced = 2,  // Coalesced onto an in-flight batch that subsequently committed
        IdempotencyConflict = 3, // Same event_id submitted with different payload fingerprint
        ValidationRejected = 4,  // Failed schema, UUIDv7, skew, or sensitive-data validation
        UnauthorizedProducer = 5, // Failed mTLS producer identity binding
        QueueOverloaded = 6,     // BoundedIngestionQueue full (backpressure)
        PersistenceFailed = 7,   // ClickHouse insert failed deterministically (connection refused, 5xx)
        PersistenceAmbiguous = 8 // ClickHouse timeout/disconnect after send; commit unknown
    };

    struct PersistAckResult {
        IngestionOutcomeStatus status{IngestionOutcomeStatus::PersistenceFailed};
        domain::EventId event_id{};
        std::chrono::system_clock::time_point received_at{};
        std::string error_code;
        std::string diagnostic_message; // Strictly sanitized; zero raw payloads
    };

} // namespace securecloud::audit::ingestion

namespace securecloud::audit::service {

    struct IngestionResult {
        bool success{false};
        ingestion::IngestionOutcomeStatus outcome_status{ingestion::IngestionOutcomeStatus::PersistenceFailed};
        std::string error_code{};
        std::string error_message{};
        std::chrono::system_clock::time_point received_at{};
    };

} // namespace securecloud::audit::service