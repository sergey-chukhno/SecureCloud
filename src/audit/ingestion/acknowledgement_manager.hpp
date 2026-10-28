#pragma once

#include "ingestion/batch_aggregator.hpp"
#include "service/audit_ingestion_service.hpp"

#include <string>

namespace securecloud::audit::ingestion {

/// Manages the resolution of durability guarantees (promises and callbacks) for ingested event batches.
class AcknowledgementManager {
  public:
    /// Completes all promises and callbacks in the batch with affirmative success status.
    static void complete_batch_success(const IngestionBatch& batch);

    /// Completes all promises and callbacks in the batch with failure details (causing producer retry).
    static void complete_batch_failure(const IngestionBatch& batch, const std::string& error_code,
                                       const std::string& error_message);
};

} // namespace securecloud::audit::ingestion