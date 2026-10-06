#include "service/audit_event_publisher.hpp"

#include <iostream>

namespace securecloud::auth::service {

void StandardLogAuditSink::emit(const domain::AuditEvent& /*event*/, std::string_view json_payload) {
    // In production environments, this outputs to structured logging pipe or stdout
    std::clog << "[AUDIT_EVENT] " << json_payload << "\n";
}

AuditEventPublisher::AuditEventPublisher(std::shared_ptr<IAuditEventSink> sink) : sink_(std::move(sink)) {
    if (!sink_) {
        sink_ = std::make_shared<StandardLogAuditSink>();
    }
}

void AuditEventPublisher::publish(const domain::AuditEvent& event) noexcept {
    try {
        if (sink_) {
            std::string json_str = event.to_json();
            sink_->emit(event, json_str);
        }
    } catch (...) {
        // Fail-safe guarantee: audit publishing errors must never disrupt authentication flows
    }
}

} // namespace securecloud::auth::service
