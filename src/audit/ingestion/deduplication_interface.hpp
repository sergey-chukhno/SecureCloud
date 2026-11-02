#pragma once

#include "domain/event_id.hpp"

#include <cstdint>

namespace securecloud::audit::ingestion {

/// Abstract interface for audit event deduplication engines.
class IDeduplicationManager {
  public:
    virtual ~IDeduplicationManager() = default;

    /// Evaluates whether an event ID has already been processed within the retention window.
    [[nodiscard]] virtual bool is_duplicate(const domain::EventId& event_id, uint64_t occurred_at_ms) = 0;

    /// Registers a successfully validated event ID in the deduplication tracking store.
    virtual void record_processed(const domain::EventId& event_id, uint64_t occurred_at_ms) = 0;
};

} // namespace securecloud::audit::ingestion