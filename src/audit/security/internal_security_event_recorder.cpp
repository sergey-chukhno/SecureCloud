#include "security/internal_security_event_recorder.hpp"

namespace securecloud::audit::security {

InternalSecurityEventRecorder::InternalSecurityEventRecorder(
    std::shared_ptr<service::AuditIngestionService> ingestion_service, std::string service_instance_name)
    : ingestion_service_(std::move(ingestion_service)), factory_(std::move(service_instance_name)) {}

bool InternalSecurityEventRecorder::record_event(InternalSecurityEventType type,
                                                 const SecurityEventContext& context) noexcept {
    if (!ingestion_service_) {
        events_dropped_count_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    AntiRecursionGuard guard;
    if (!guard.acquired()) {
        events_dropped_count_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    try {
        domain::AuditEvent event = factory_.create_event(type, context);

        if (!should_record_internal_event(event)) {
            events_dropped_count_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        auto result = ingestion_service_->ingest_single(event);
        if (result.success) {
            events_recorded_count_.fetch_add(1, std::memory_order_relaxed);
            return true;
        } else {
            events_dropped_count_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
    } catch (...) {
        events_dropped_count_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
}

std::uint64_t InternalSecurityEventRecorder::events_recorded_count() const noexcept {
    return events_recorded_count_.load(std::memory_order_relaxed);
}

std::uint64_t InternalSecurityEventRecorder::events_dropped_count() const noexcept {
    return events_dropped_count_.load(std::memory_order_relaxed);
}

std::uint64_t InternalSecurityEventRecorder::recursion_prevented_count() const noexcept {
    return get_recursion_prevented_count();
}

} // namespace securecloud::audit::security
