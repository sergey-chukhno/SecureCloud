#include "auth/service/audit_event_publisher.hpp"

#include "auth/domain/auth_outbox_entity.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/service/outbox_event_mapper.hpp"

#include <chrono>
#include <iostream>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <utility>

namespace securecloud::auth::service {

namespace {

[[nodiscard]] domain::AuthOutboxEntity build_outbox_entity(const domain::AuditEvent& event,
                                                           std::string_view producer_instance) {
    return OutboxEventMapper::to_outbox_entity(event, producer_instance);
}

} // namespace

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

OutboxAuditEventPublisher::OutboxAuditEventPublisher(std::shared_ptr<repository::IAuthOutboxRepository> outbox_repo,
                                                     std::string producer_instance,
                                                     std::shared_ptr<IAuditEventSink> fallback_sink,
                                                     audit::AuthOutboxMetrics* metrics)
    : outbox_repo_(std::move(outbox_repo)), producer_instance_(std::move(producer_instance)),
      fallback_sink_(std::move(fallback_sink)),
      metrics_(metrics != nullptr ? metrics : &audit::AuthOutboxMetrics::instance()) {
    if (!outbox_repo_) {
        throw std::invalid_argument("OutboxAuditEventPublisher requires non-null IAuthOutboxRepository");
    }
    if (!fallback_sink_) {
        fallback_sink_ = std::make_shared<StandardLogAuditSink>();
    }
}

void OutboxAuditEventPublisher::publish_in_tx(const domain::AuditEvent& event, pqxx::transaction_base& tx) {
    domain::AuthOutboxEntity entity = build_outbox_entity(event, producer_instance_);
    outbox_repo_->stage_event(entity, tx);
    metrics_->record_event_staged(audit::StagingCategory::Transactional, 1);
    metrics_->increment_pending_events(1);
}

void OutboxAuditEventPublisher::publish(const domain::AuditEvent& event) noexcept {
    try {
        domain::AuthOutboxEntity entity = build_outbox_entity(event, producer_instance_);
        outbox_repo_->stage_event(entity);
        metrics_->record_event_staged(audit::StagingCategory::Autonomous, 1);
        metrics_->increment_pending_events(1);
    } catch (...) {
        // Fail-safe guarantee for Category B autonomous events: fall back to structured log sink
        try {
            if (fallback_sink_) {
                const std::string json_str = event.to_json();
                fallback_sink_->emit(event, json_str);
            }
        } catch (...) {
        }
    }
}

} // namespace securecloud::auth::service
