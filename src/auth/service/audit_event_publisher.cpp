#include "auth/service/audit_event_publisher.hpp"

#include "auth/domain/auth_outbox_entity.hpp"
#include "auth/domain/uuid.hpp"

#include <chrono>
#include <iostream>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <utility>

namespace securecloud::auth::service {

namespace {

[[nodiscard]] domain::AuthOutboxEntity build_outbox_entity(const domain::AuditEvent& event,
                                                           std::string_view producer_instance) {
    const std::string raw_json = event.to_json();
    nlohmann::json payload = nlohmann::json::parse(raw_json);

    domain::Uuid event_id = domain::Uuid::generate_v7();
    if (payload.contains("event_id") && payload["event_id"].is_string()) {
        if (auto parsed = domain::Uuid::from_string(payload["event_id"].get<std::string>());
            parsed.has_value() && !parsed->is_nil()) {
            event_id = *parsed;
        }
    }
    payload["event_id"] = event_id.to_string();

    if (!payload.contains("producer_service") || !payload["producer_service"].is_string() ||
        payload["producer_service"].get<std::string>().empty()) {
        payload["producer_service"] = "AUTH";
    }
    if (!payload.contains("producer_instance") || !payload["producer_instance"].is_string() ||
        payload["producer_instance"].get<std::string>().empty()) {
        payload["producer_instance"] = std::string(producer_instance);
    }

    const std::string event_type = payload.value("event_type", "auth.unspecified");
    const std::string severity_str = payload.value("severity", "INFO");
    const domain::OutboxSeverity severity =
        domain::parse_outbox_severity(severity_str).value_or(domain::OutboxSeverity::Info);

    std::string aggregate_type = payload.value("target_type", "");
    if (aggregate_type.empty()) {
        aggregate_type = payload.value("aggregate_type", "AUTH");
    }

    std::optional<domain::Uuid> aggregate_id = std::nullopt;
    if (payload.contains("target_id") && payload["target_id"].is_string()) {
        aggregate_id = domain::Uuid::from_string(payload["target_id"].get<std::string>());
    }
    if (!aggregate_id.has_value() && payload.contains("actor_id") && payload["actor_id"].is_string()) {
        aggregate_id = domain::Uuid::from_string(payload["actor_id"].get<std::string>());
    }

    domain::AuthOutboxEntity entity;
    entity.event_id = event_id;
    entity.aggregate_type = std::move(aggregate_type);
    entity.aggregate_id = aggregate_id;
    entity.event_type = event_type;
    entity.severity = severity;
    entity.payload_json = payload.dump();
    entity.status = domain::OutboxStatus::Pending;
    entity.retry_count = 0;
    entity.created_at = std::chrono::system_clock::now();

    return entity;
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
