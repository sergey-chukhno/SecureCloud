#include "files/audit/files_audit_mapper.hpp"

#include <nlohmann/json.hpp>

namespace securecloud::files::audit {

securecloud::audit::v1::AuditEventProto FilesAuditMapper::to_proto(const FilesOutboxEntity& entity) {
    securecloud::audit::v1::AuditEventProto proto;
    proto.set_event_id(entity.event_id);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(entity.created_at.time_since_epoch()).count();
    proto.set_occurred_at_ms(ms);
    proto.set_event_type(entity.event_type);

    // Producer service is Files
    proto.set_producer_service(securecloud::audit::v1::ProducerServiceProto::PRODUCER_SERVICE_FILES);
    proto.set_producer_instance("files-daemon");

    // Default target
    proto.set_target_type(securecloud::audit::v1::TargetTypeProto::TARGET_TYPE_FILE);
    proto.set_target_id(entity.aggregate_id);

    // Default actor
    proto.set_actor_type(securecloud::audit::v1::ActorTypeProto::ACTOR_TYPE_USER);

    // Severity mapping
    if (entity.event_type == "FILE_ACCESS_REVOKED" || entity.event_type == "CAPABILITY_REJECTED") {
        proto.set_severity(securecloud::audit::v1::SeverityProto::SEVERITY_SECURITY);
    } else {
        proto.set_severity(securecloud::audit::v1::SeverityProto::SEVERITY_INFO);
    }

    // Parse payload for safe metadata and actor info
    try {
        if (!entity.payload_json.empty()) {
            auto payload = nlohmann::json::parse(entity.payload_json);

            // Extract actor
            if (payload.contains("owner_user_id") && payload["owner_user_id"].is_string()) {
                proto.set_actor_id(payload["owner_user_id"].get<std::string>());
            } else if (payload.contains("user_id") && payload["user_id"].is_string()) {
                proto.set_actor_id(payload["user_id"].get<std::string>());
            } else if (payload.contains("caller_user_id") && payload["caller_user_id"].is_string()) {
                proto.set_actor_id(payload["caller_user_id"].get<std::string>());
            }

            // Extract correlation ID if present
            if (payload.contains("request_id") && payload["request_id"].is_string()) {
                proto.set_correlation_id(payload["request_id"].get<std::string>());
            } else if (payload.contains("correlation_id") && payload["correlation_id"].is_string()) {
                proto.set_correlation_id(payload["correlation_id"].get<std::string>());
            } else {
                proto.set_correlation_id(entity.event_id);
            }

            auto* meta_map = proto.mutable_metadata();

            // Populate only strictly safe metadata keys
            for (const auto& [key, val] : payload.items()) {
                // Filter out any sensitive / plaintext / ciphertext data
                if (key == "encryption_key" || key == "key" || key == "secret" || key == "token" ||
                    key == "ciphertext" || key == "data" || key == "encrypted_data" || key == "password") {
                    continue;
                }

                if (val.is_string()) {
                    (*meta_map)[key] = val.get<std::string>();
                } else if (val.is_number()) {
                    (*meta_map)[key] = val.dump();
                } else if (val.is_boolean()) {
                    (*meta_map)[key] = val.get<bool>() ? "true" : "false";
                }
            }
        }
    } catch (...) {
        // Fallback for malformed JSON: do not fail translation, preserve correlation ID
        proto.set_correlation_id(entity.event_id);
    }

    if (proto.actor_id().empty()) {
        proto.set_actor_id("system");
        proto.set_actor_type(securecloud::audit::v1::ActorTypeProto::ACTOR_TYPE_SYSTEM);
    }

    return proto;
}

} // namespace securecloud::files::audit
