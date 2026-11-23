#pragma once

#include "domain/enums.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

namespace securecloud::audit::security {

/// Internal security event catalog for the Audit Service runtime.
enum class InternalSecurityEventType : uint16_t {
    UnauthenticatedConnection = 1,
    ProducerIdentityMismatch = 2,
    UntrustedClientCertificate = 3,
    SensitiveDataDetected = 4,
    MalformedPayloadStructure = 5,
    ExcessiveClockSkew = 6,
    OversizedBatchRejected = 7,
    IngestionQueueSaturated = 8,
    PersistenceStorageFailure = 9,
    ServiceStarted = 10,
    ServiceDraining = 11
};

/// Maps an internal security event type to its canonical string representation.
[[nodiscard]] constexpr std::string_view to_event_type_string(InternalSecurityEventType type) noexcept {
    switch (type) {
    case InternalSecurityEventType::UnauthenticatedConnection:
        return "audit.security.auth.unauthenticated_connection";
    case InternalSecurityEventType::ProducerIdentityMismatch:
        return "audit.security.auth.producer_identity_mismatch";
    case InternalSecurityEventType::UntrustedClientCertificate:
        return "audit.security.auth.untrusted_client_cert";
    case InternalSecurityEventType::SensitiveDataDetected:
        return "audit.security.payload.sensitive_data_detected";
    case InternalSecurityEventType::MalformedPayloadStructure:
        return "audit.security.payload.malformed_structure";
    case InternalSecurityEventType::ExcessiveClockSkew:
        return "audit.security.payload.excessive_clock_skew";
    case InternalSecurityEventType::OversizedBatchRejected:
        return "audit.security.payload.oversized_batch_rejected";
    case InternalSecurityEventType::IngestionQueueSaturated:
        return "audit.security.capacity.queue_saturated";
    case InternalSecurityEventType::PersistenceStorageFailure:
        return "audit.security.storage.persistence_failure";
    case InternalSecurityEventType::ServiceStarted:
        return "audit.security.lifecycle.service_started";
    case InternalSecurityEventType::ServiceDraining:
        return "audit.security.lifecycle.service_draining";
    }
    return "audit.security.unknown";
}

/// Maps an internal security event type to its canonical Severity level.
[[nodiscard]] constexpr domain::Severity to_severity(InternalSecurityEventType type) noexcept {
    switch (type) {
    case InternalSecurityEventType::UnauthenticatedConnection:
    case InternalSecurityEventType::ProducerIdentityMismatch:
    case InternalSecurityEventType::UntrustedClientCertificate:
        return domain::Severity::Security;
    case InternalSecurityEventType::SensitiveDataDetected:
    case InternalSecurityEventType::IngestionQueueSaturated:
    case InternalSecurityEventType::PersistenceStorageFailure:
        return domain::Severity::Critical;
    case InternalSecurityEventType::MalformedPayloadStructure:
    case InternalSecurityEventType::ExcessiveClockSkew:
    case InternalSecurityEventType::OversizedBatchRejected:
        return domain::Severity::Warning;
    case InternalSecurityEventType::ServiceStarted:
    case InternalSecurityEventType::ServiceDraining:
        return domain::Severity::Info;
    }
    return domain::Severity::Warning;
}

/// Returns default ActorType for the given internal security event.
[[nodiscard]] constexpr domain::ActorType to_default_actor_type(InternalSecurityEventType type) noexcept {
    switch (type) {
    case InternalSecurityEventType::UnauthenticatedConnection:
    case InternalSecurityEventType::UntrustedClientCertificate:
        return domain::ActorType::Unknown;
    case InternalSecurityEventType::ProducerIdentityMismatch:
    case InternalSecurityEventType::SensitiveDataDetected:
    case InternalSecurityEventType::MalformedPayloadStructure:
    case InternalSecurityEventType::ExcessiveClockSkew:
    case InternalSecurityEventType::OversizedBatchRejected:
        return domain::ActorType::Service;
    case InternalSecurityEventType::IngestionQueueSaturated:
    case InternalSecurityEventType::PersistenceStorageFailure:
    case InternalSecurityEventType::ServiceStarted:
    case InternalSecurityEventType::ServiceDraining:
        return domain::ActorType::System;
    }
    return domain::ActorType::Unknown;
}

/// Returns default TargetType for internal security events.
[[nodiscard]] constexpr domain::TargetType to_default_target_type(InternalSecurityEventType type) noexcept {
    (void)type;
    return domain::TargetType::Service;
}

constexpr size_t kMaxInternalMetadataPairs = 10;
constexpr size_t kMaxInternalMetadataKeyLength = 64;
constexpr size_t kMaxInternalMetadataValueLength = 256;

/// Checks if a metadata key contains prohibited credential terms (token, auth, password, key, secret).
[[nodiscard]] bool is_prohibited_metadata_key(std::string_view key) noexcept;

/// Validates a single metadata key-value pair against size bounds and prohibited terms.
[[nodiscard]] bool validate_internal_metadata_key_value(std::string_view key, std::string_view value) noexcept;

/// Validates an entire metadata map against bounds (<= 10 pairs, valid keys/values).
[[nodiscard]] bool validate_internal_metadata(const std::unordered_map<std::string, std::string>& metadata) noexcept;

} // namespace securecloud::audit::security
