#include "auth/service/outbox_event_mapper.hpp"

#include <chrono>
#include <nlohmann/json.hpp>
#include <stdexcept>

namespace securecloud::auth::service {

namespace {

[[nodiscard]] domain::OutboxSeverity map_event_type_to_severity(domain::AuditEventType type) noexcept {
    switch (type) {
    case domain::AuditEventType::TokenReuseDetected:
        return domain::OutboxSeverity::Critical;

    case domain::AuditEventType::AccountDisabledAccessAttempt:
    case domain::AuditEventType::PrekeyInventoryExhausted:
        return domain::OutboxSeverity::Security;

    case domain::AuditEventType::LoginFailed:
    case domain::AuditEventType::SessionExpiredAttempt:
    case domain::AuditEventType::SessionRevokedAttempt:
    case domain::AuditEventType::MfaChallengeFailed:
    case domain::AuditEventType::MfaDisabled:
    case domain::AuditEventType::DeviceRevoked:
    case domain::AuditEventType::PrekeyInventoryLow:
        return domain::OutboxSeverity::Warning;

    case domain::AuditEventType::LoginSucceeded:
    case domain::AuditEventType::SessionRevoked:
    case domain::AuditEventType::TokenRefreshed:
    case domain::AuditEventType::MfaEnrollmentInitiated:
    case domain::AuditEventType::MfaEnrollmentConfirmed:
    case domain::AuditEventType::MfaChallengeCreated:
    case domain::AuditEventType::MfaChallengeSucceeded:
    case domain::AuditEventType::MfaRecoveryCodeUsed:
    case domain::AuditEventType::DeviceEnrolled:
    case domain::AuditEventType::DevicePairingInitiated:
    case domain::AuditEventType::DeviceAuthorized:
    case domain::AuditEventType::PrekeysUpdated:
    case domain::AuditEventType::SignedPrekeyRotated:
        return domain::OutboxSeverity::Info;
    }
    return domain::OutboxSeverity::Info;
}

[[nodiscard]] bool is_device_centric_event(domain::AuditEventType type) noexcept {
    switch (type) {
    case domain::AuditEventType::DeviceEnrolled:
    case domain::AuditEventType::DevicePairingInitiated:
    case domain::AuditEventType::DeviceAuthorized:
    case domain::AuditEventType::DeviceRevoked:
    case domain::AuditEventType::PrekeysUpdated:
    case domain::AuditEventType::SignedPrekeyRotated:
    case domain::AuditEventType::PrekeyInventoryLow:
    case domain::AuditEventType::PrekeyInventoryExhausted:
        return true;
    default:
        return false;
    }
}

[[nodiscard]] securecloud::audit::v1::SeverityProto map_severity_to_proto(std::string_view sev) noexcept {
    if (sev == "WARNING") {
        return securecloud::audit::v1::SEVERITY_WARNING;
    }
    if (sev == "SECURITY") {
        return securecloud::audit::v1::SEVERITY_SECURITY;
    }
    if (sev == "CRITICAL") {
        return securecloud::audit::v1::SEVERITY_CRITICAL;
    }
    return securecloud::audit::v1::SEVERITY_INFO;
}

[[nodiscard]] securecloud::audit::v1::ActorTypeProto map_actor_type_to_proto(std::string_view actor) noexcept {
    if (actor == "USER") {
        return securecloud::audit::v1::ACTOR_TYPE_USER;
    }
    if (actor == "DEVICE") {
        return securecloud::audit::v1::ACTOR_TYPE_DEVICE;
    }
    if (actor == "SERVICE") {
        return securecloud::audit::v1::ACTOR_TYPE_SERVICE;
    }
    if (actor == "SYSTEM") {
        return securecloud::audit::v1::ACTOR_TYPE_SYSTEM;
    }
    return securecloud::audit::v1::ACTOR_TYPE_UNSPECIFIED;
}

[[nodiscard]] securecloud::audit::v1::TargetTypeProto map_target_type_to_proto(std::string_view target) noexcept {
    if (target == "USER") {
        return securecloud::audit::v1::TARGET_TYPE_USER;
    }
    if (target == "DEVICE") {
        return securecloud::audit::v1::TARGET_TYPE_DEVICE;
    }
    if (target == "CONVERSATION") {
        return securecloud::audit::v1::TARGET_TYPE_CONVERSATION;
    }
    if (target == "FILE") {
        return securecloud::audit::v1::TARGET_TYPE_FILE;
    }
    if (target == "SERVICE") {
        return securecloud::audit::v1::TARGET_TYPE_SERVICE;
    }
    return securecloud::audit::v1::TARGET_TYPE_UNSPECIFIED;
}

} // namespace

domain::AuthOutboxEntity OutboxEventMapper::to_outbox_entity(const domain::AuditEvent& event,
                                                             std::string_view default_producer_instance) {
    const domain::Uuid eid = event.event_id.is_nil() ? domain::Uuid::generate_v7() : event.event_id;
    const auto occurred_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(event.timestamp.time_since_epoch()).count();

    const std::string event_type_str(domain::to_string(event.event_type));
    const domain::OutboxSeverity outbox_sev = map_event_type_to_severity(event.event_type);
    const std::string sev_str(domain::to_string(outbox_sev));

    std::string actor_type_str = "SYSTEM";
    std::string actor_id_str = event.credential_identifier.empty() ? "anonymous" : event.credential_identifier;
    if (event.user_id.has_value()) {
        actor_type_str = "USER";
        actor_id_str = event.user_id->to_string();
    } else if (event.device_id.has_value()) {
        actor_type_str = "DEVICE";
        actor_id_str = event.device_id->to_string();
    }

    std::string target_type_str = "USER";
    std::string target_id_str = event.credential_identifier;
    std::string aggregate_type_str = "AUTH";
    std::optional<domain::Uuid> aggregate_id = std::nullopt;

    if (is_device_centric_event(event.event_type) && event.device_id.has_value()) {
        target_type_str = "DEVICE";
        target_id_str = event.device_id->to_string();
        aggregate_type_str = "DEVICE";
        aggregate_id = *event.device_id;
    } else if (event.user_id.has_value()) {
        target_type_str = "USER";
        target_id_str = event.user_id->to_string();
        aggregate_type_str = "USER";
        aggregate_id = *event.user_id;
    } else if (event.device_id.has_value()) {
        target_type_str = "DEVICE";
        target_id_str = event.device_id->to_string();
        aggregate_type_str = "DEVICE";
        aggregate_id = *event.device_id;
    } else if (event.session_id.has_value()) {
        target_type_str = "SERVICE";
        target_id_str = event.session_id->to_string();
        aggregate_type_str = "SESSION";
        aggregate_id = *event.session_id;
    }

    nlohmann::json metadata = nlohmann::json::object();
    metadata["client_ip"] = event.client_ip;
    if (!event.credential_identifier.empty()) {
        metadata["credential_identifier"] = event.credential_identifier;
    }
    if (event.user_id.has_value()) {
        metadata["user_id"] = event.user_id->to_string();
    }
    if (event.device_id.has_value()) {
        metadata["device_id"] = event.device_id->to_string();
    }
    if (event.session_id.has_value()) {
        metadata["session_id"] = event.session_id->to_string();
    }
    if (!event.failure_reason.empty()) {
        metadata["failure_reason"] = event.failure_reason;
    }

    const std::string correlation_id = event.session_id.has_value() ? event.session_id->to_string() : eid.to_string();

    nlohmann::json payload = {
        {"event_id", eid.to_string()},      {"occurred_at_ms", occurred_ms},
        {"event_type", event_type_str},     {"severity", sev_str},
        {"producer_service", "AUTH"},       {"producer_instance", std::string(default_producer_instance)},
        {"actor_type", actor_type_str},     {"actor_id", actor_id_str},
        {"target_type", target_type_str},   {"target_id", target_id_str},
        {"correlation_id", correlation_id}, {"metadata", metadata},
    };

    domain::AuthOutboxEntity entity;
    entity.event_id = eid;
    entity.aggregate_type = aggregate_type_str;
    entity.aggregate_id = aggregate_id;
    entity.event_type = event_type_str;
    entity.severity = outbox_sev;
    entity.payload_json = payload.dump();
    entity.status = domain::OutboxStatus::Pending;
    entity.retry_count = 0;
    entity.created_at = event.timestamp;

    return entity;
}

securecloud::audit::v1::AuditEventProto OutboxEventMapper::to_audit_proto(const domain::AuthOutboxEntity& entity) {
    nlohmann::json j = nlohmann::json::parse(entity.payload_json);

    securecloud::audit::v1::AuditEventProto proto;
    proto.set_event_id(j.value("event_id", entity.event_id.to_string()));
    proto.set_occurred_at_ms(j.at("occurred_at_ms").get<int64_t>());
    proto.set_event_type(j.value("event_type", entity.event_type));
    proto.set_severity(map_severity_to_proto(j.value("severity", std::string(domain::to_string(entity.severity)))));
    proto.set_producer_service(securecloud::audit::v1::PRODUCER_SERVICE_AUTH);
    proto.set_producer_instance(j.value("producer_instance", "auth-1"));
    proto.set_actor_type(map_actor_type_to_proto(j.value("actor_type", "UNKNOWN")));
    proto.set_actor_id(j.value("actor_id", ""));
    proto.set_target_type(map_target_type_to_proto(j.value("target_type", "UNKNOWN")));
    proto.set_target_id(j.value("target_id", ""));
    proto.set_correlation_id(j.value("correlation_id", ""));

    if (j.contains("causation_id") && j["causation_id"].is_string()) {
        proto.set_causation_id(j["causation_id"].get<std::string>());
    }

    if (j.contains("metadata") && j["metadata"].is_object()) {
        auto* meta_map = proto.mutable_metadata();
        for (const auto& [k, v] : j["metadata"].items()) {
            if (v.is_string()) {
                (*meta_map)[k] = v.get<std::string>();
            } else {
                (*meta_map)[k] = v.dump();
            }
        }
    }

    return proto;
}

} // namespace securecloud::auth::service
