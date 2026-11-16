#include "gateway_audit_event_factory.hpp"

#include "domain/enums.hpp"
#include "domain/event_id.hpp"
#include "domain/sensitive_data_guard.hpp"

#include <algorithm>
#include <regex>
#include <set>
#include <stdexcept>

namespace securecloud::gateway::audit {

namespace {

const std::regex kUuidRegex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

constexpr size_t kMaxProducerInstanceLength = 64;
constexpr size_t kMaxMetadataValueLength = 1024;

securecloud::audit::domain::Severity map_severity(AuditSeverity severity) noexcept {
    switch (severity) {
    case AuditSeverity::Info:
        return securecloud::audit::domain::Severity::Info;
    case AuditSeverity::Warning:
        return securecloud::audit::domain::Severity::Warning;
    case AuditSeverity::Security:
        return securecloud::audit::domain::Severity::Security;
    case AuditSeverity::Critical:
        return securecloud::audit::domain::Severity::Critical;
    }
    return securecloud::audit::domain::Severity::Info;
}

bool is_whitelisted_metadata_key(GatewayAuditEventType type, std::string_view key) noexcept {
    // Universal request context keys allowed for all events
    if (key == "client_ip" || key == "route_class" || key == "http_method" || key == "device_id") {
        return true;
    }

    switch (type) {
    case GatewayAuditEventType::TokenRejected:
        return key == "reason";
    case GatewayAuditEventType::AuthorizationDenied:
        return key == "reason" || key == "required_scope";
    case GatewayAuditEventType::IdentityHeaderStripped:
        return key == "header_names" || key == "count";
    case GatewayAuditEventType::ChunkIntegrityRejected:
        return key == "chunk_index" || key == "reason";
    case GatewayAuditEventType::RateLimitExceeded:
        return key == "window_start" || key == "window_seconds" || key == "rejected_count" || key == "key_type";
    case GatewayAuditEventType::RequestRejected:
        return key == "reason" || key == "rejected_count" || key == "window";
    case GatewayAuditEventType::CircuitOpened:
    case GatewayAuditEventType::CircuitClosed:
        return key == "dependency" || key == "failure_count";
    case GatewayAuditEventType::LifecycleStarted:
    case GatewayAuditEventType::LifecycleDrainStarted:
    case GatewayAuditEventType::LifecycleStopped:
        return key == "version" || key == "pending_audit_events";
    case GatewayAuditEventType::EventsLost:
        return key == "lost_count" || key == "reason";
    }
    return false;
}

} // namespace

GatewayAuditEventFactory::GatewayAuditEventFactory(std::string producer_instance)
    : producer_instance_(std::move(producer_instance)) {
    if (producer_instance_.length() > kMaxProducerInstanceLength) {
        producer_instance_.resize(kMaxProducerInstanceLength);
    }
}

std::string GatewayAuditEventFactory::sanitize_correlation_id(const std::optional<std::string>& raw_id) {
    if (raw_id.has_value() && std::regex_match(*raw_id, kUuidRegex)) {
        return *raw_id;
    }
    // Generate fresh UUIDv7 if missing or malformed client-supplied ID
    return securecloud::audit::domain::EventId::generate_v7().to_string();
}

std::map<std::string, std::string>
GatewayAuditEventFactory::sanitize_metadata(GatewayAuditEventType type,
                                            const GatewayAuditObservation& observation) const {
    std::map<std::string, std::string> clean_metadata;

    // Standard context entries
    clean_metadata["client_ip"] = observation.client_ip;
    clean_metadata["route_class"] = observation.route_class;
    clean_metadata["http_method"] = observation.http_method;

    if (observation.device_id.has_value() && !observation.device_id->empty()) {
        clean_metadata["device_id"] = *observation.device_id;
    }

    // Process whitelisted observation metadata
    for (const auto& [key, raw_value] : observation.metadata) {
        if (!is_whitelisted_metadata_key(type, key)) {
            continue;
        }

        std::string clean_value = raw_value;
        if (clean_value.length() > kMaxMetadataValueLength) {
            clean_value.resize(kMaxMetadataValueLength);
        }

        clean_metadata[key] = securecloud::audit::domain::SensitiveDataGuard::sanitize_diagnostic(clean_value);
    }

    return clean_metadata;
}

securecloud::audit::domain::AuditEvent
GatewayAuditEventFactory::create_domain_event(const GatewayAuditObservation& observation) const {
    securecloud::audit::domain::AuditEvent event;

    event.event_id = securecloud::audit::domain::EventId::generate_v7();
    event.occurred_at = observation.occurred_at;
    event.event_type = std::string(to_event_type_string(observation.type));

    const auto severity = observation.override_severity.value_or(get_default_severity(observation.type));
    event.severity = map_severity(severity);

    event.producer_service = securecloud::audit::domain::ProducerService::Gateway;
    event.producer_instance = producer_instance_;

    // Trusted actor attribution
    if (observation.actor_id.has_value() && !observation.actor_id->empty()) {
        event.actor_type = securecloud::audit::domain::ActorType::User;
        event.actor_id = *observation.actor_id;
    } else {
        event.actor_type = securecloud::audit::domain::ActorType::Unknown;
        event.actor_id.clear();
    }

    // Target attribution
    event.target_type = securecloud::audit::domain::TargetType::Service;
    event.target_id = observation.target_id;

    // Hardened correlation ID
    event.correlation_id = sanitize_correlation_id(observation.client_request_id);

    // Sanitized & whitelisted metadata
    const auto clean_meta = sanitize_metadata(observation.type, observation);
    for (const auto& [k, v] : clean_meta) {
        event.metadata[k] = v;
    }

    // Local validation check
    const auto val_result = validator_.validate(event);
    if (!val_result.is_valid()) {
        std::string err_details = "Validation failed";
        if (!val_result.errors().empty()) {
            const auto& first_err = val_result.errors().front();
            err_details = std::string(securecloud::audit::domain::to_string(first_err.code));
            if (!first_err.message.empty()) {
                err_details += ": " + first_err.message;
            }
        }
        throw std::invalid_argument("GatewayAuditEventFactory created invalid event: " + err_details);
    }

    return event;
}

::securecloud::audit::v1::AuditEventProto
GatewayAuditEventFactory::to_protobuf(const securecloud::audit::domain::AuditEvent& domain_event) {
    ::securecloud::audit::v1::AuditEventProto proto;

    proto.set_event_id(domain_event.event_id.to_string());

    const auto duration = domain_event.occurred_at.time_since_epoch();
    const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    proto.set_occurred_at_ms(millis);

    proto.set_event_type(domain_event.event_type);

    switch (domain_event.severity) {
    case securecloud::audit::domain::Severity::Info:
        proto.set_severity(::securecloud::audit::v1::SEVERITY_INFO);
        break;
    case securecloud::audit::domain::Severity::Warning:
        proto.set_severity(::securecloud::audit::v1::SEVERITY_WARNING);
        break;
    case securecloud::audit::domain::Severity::Security:
        proto.set_severity(::securecloud::audit::v1::SEVERITY_SECURITY);
        break;
    case securecloud::audit::domain::Severity::Critical:
        proto.set_severity(::securecloud::audit::v1::SEVERITY_CRITICAL);
        break;
    }

    switch (domain_event.producer_service) {
    case securecloud::audit::domain::ProducerService::Gateway:
        proto.set_producer_service(::securecloud::audit::v1::PRODUCER_SERVICE_GATEWAY);
        break;
    case securecloud::audit::domain::ProducerService::Auth:
        proto.set_producer_service(::securecloud::audit::v1::PRODUCER_SERVICE_AUTH);
        break;
    case securecloud::audit::domain::ProducerService::Messaging:
        proto.set_producer_service(::securecloud::audit::v1::PRODUCER_SERVICE_MESSAGING);
        break;
    case securecloud::audit::domain::ProducerService::Files:
        proto.set_producer_service(::securecloud::audit::v1::PRODUCER_SERVICE_FILES);
        break;
    case securecloud::audit::domain::ProducerService::Audit:
        proto.set_producer_service(::securecloud::audit::v1::PRODUCER_SERVICE_AUDIT);
        break;
    default:
        proto.set_producer_service(::securecloud::audit::v1::PRODUCER_SERVICE_UNSPECIFIED);
        break;
    }

    proto.set_producer_instance(domain_event.producer_instance);

    switch (domain_event.actor_type) {
    case securecloud::audit::domain::ActorType::User:
        proto.set_actor_type(::securecloud::audit::v1::ACTOR_TYPE_USER);
        break;
    case securecloud::audit::domain::ActorType::Device:
        proto.set_actor_type(::securecloud::audit::v1::ACTOR_TYPE_DEVICE);
        break;
    case securecloud::audit::domain::ActorType::Service:
        proto.set_actor_type(::securecloud::audit::v1::ACTOR_TYPE_SERVICE);
        break;
    case securecloud::audit::domain::ActorType::System:
        proto.set_actor_type(::securecloud::audit::v1::ACTOR_TYPE_SYSTEM);
        break;
    default:
        proto.set_actor_type(::securecloud::audit::v1::ACTOR_TYPE_UNSPECIFIED);
        break;
    }
    proto.set_actor_id(domain_event.actor_id);

    switch (domain_event.target_type) {
    case securecloud::audit::domain::TargetType::User:
        proto.set_target_type(::securecloud::audit::v1::TARGET_TYPE_USER);
        break;
    case securecloud::audit::domain::TargetType::Device:
        proto.set_target_type(::securecloud::audit::v1::TARGET_TYPE_DEVICE);
        break;
    case securecloud::audit::domain::TargetType::Conversation:
        proto.set_target_type(::securecloud::audit::v1::TARGET_TYPE_CONVERSATION);
        break;
    case securecloud::audit::domain::TargetType::File:
        proto.set_target_type(::securecloud::audit::v1::TARGET_TYPE_FILE);
        break;
    case securecloud::audit::domain::TargetType::Service:
        proto.set_target_type(::securecloud::audit::v1::TARGET_TYPE_SERVICE);
        break;
    default:
        proto.set_target_type(::securecloud::audit::v1::TARGET_TYPE_UNSPECIFIED);
        break;
    }
    proto.set_target_id(domain_event.target_id);

    proto.set_correlation_id(domain_event.correlation_id);

    auto* mutable_meta = proto.mutable_metadata();
    for (const auto& [k, v] : domain_event.metadata) {
        (*mutable_meta)[k] = v;
    }

    return proto;
}

std::vector<uint8_t>
GatewayAuditEventFactory::serialize_canonical_proto(const ::securecloud::audit::v1::AuditEventProto& proto_event) {
    const auto size = proto_event.ByteSizeLong();
    std::vector<uint8_t> buffer(size);
    if (!proto_event.SerializeToArray(buffer.data(), static_cast<int>(size))) {
        throw std::runtime_error("Failed to serialize AuditEventProto to binary buffer");
    }
    return buffer;
}

} // namespace securecloud::gateway::audit
