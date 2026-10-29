#pragma once

#include "domain/audit_event.hpp"
#include "ingestion/idempotency_types.hpp"

#include <chrono>
#include <functional>
#include <future>
#include <memory>

namespace securecloud::audit::ingestion {

using CompletionCallback = std::function<void(const service::IngestionResult&)>;

struct IngestionEnvelope {
    domain::AuditEvent event{};
    std::chrono::system_clock::time_point enqueued_at{std::chrono::system_clock::now()};
    std::shared_ptr<std::promise<service::IngestionResult>> completion_promise{nullptr};
    CompletionCallback completion_callback{nullptr};
};

} // namespace securecloud::audit::ingestion