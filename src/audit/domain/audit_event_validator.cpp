#include "audit_event_validator.hpp"
#include "sensitive_data_guard.hpp"

#include <cctype>

namespace securecloud::audit::domain {

namespace {

bool is_valid_event_type_format(std::string_view type, size_t max_length) noexcept {
    if (type.empty() || type.size() > max_length) {
        return false;
    }

    bool has_dot = false;
    bool prev_was_dot = true;

    for (char c : type) {
        if (c == '.') {
            if (prev_was_dot) return false;
            has_dot = true;
            prev_was_dot = true;
        } else if (std::islower(static_cast<unsigned char>(c)) ||
                   std::isdigit(static_cast<unsigned char>(c)) ||
                   c == '_') {
            prev_was_dot = false;
        } else {
            return false;
        }
    }

    return has_dot && !prev_was_dot;
}

bool is_valid_metadata_key(std::string_view key, size_t max_length) noexcept {
    if (key.empty() || key.size() > max_length) {
        return false;
    }

    for (char c : key) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '.' && c != '-') {
            return false;
        }
    }

    return true;
}

bool is_printable_ascii_no_space(std::string_view sv) noexcept {
    for (char c : sv) {
        auto uc = static_cast<unsigned char>(c);
        if (uc <= 32 || uc >= 127) {
            return false;
        }
    }
    return true;
}

} // namespace

AuditValidationResult AuditEventValidator::validate(
    const AuditEvent& event,
    const AuditEventValidationLimits& limits,
    std::chrono::system_clock::time_point now) noexcept {

    AuditValidationResult result;
    size_t total_estimated_bytes = sizeof(AuditEvent);

    // Rule 1: Event ID validation
    if (event.event_id.is_nil()) {
        result.add_error({
            AuditValidationErrorCode::InvalidEventId,
            "event_id",
            "Event ID must not be nil"
        });
    } else if (event.event_id.version() != 7 || event.event_id.variant() != 2) {
        result.add_error({
            AuditValidationErrorCode::EventIdNotUuidV7,
            "event_id",
            "Event ID must be a valid RFC 9562 UUIDv7"
        });
    }

    // Rule 2: Event Type validation
    total_estimated_bytes += event.event_type.capacity();
    if (!is_valid_event_type_format(event.event_type, limits.max_event_type_length)) {
        result.add_error({
            AuditValidationErrorCode::InvalidEventTypeFormat,
            "event_type",
            "Event type must be dot-separated lowercase alphanumeric (e.g. 'auth.login.success') up to " +
                std::to_string(limits.max_event_type_length) + " chars"
        });
    }

    // Rule 3: Occurred At timestamp drift
    if (event.occurred_at > now + limits.max_future_skew) {
        result.add_error({
            AuditValidationErrorCode::ClockSkewFuture,
            "occurred_at",
            "Event timestamp is too far in the future (exceeds clock drift limit)"
        });
    } else if (event.occurred_at < now - limits.max_past_age) {
        result.add_error({
            AuditValidationErrorCode::ClockSkewTooOld,
            "occurred_at",
            "Event timestamp is older than the allowed retention floor"
        });
    }

    // Rule 4: Received At logic
    if (event.received_at.has_value()) {
        if (*event.received_at + limits.max_future_skew < event.occurred_at) {
            result.add_error({
                AuditValidationErrorCode::ReceivedAtBeforeOccurredAt,
                "received_at",
                "Received timestamp cannot be significantly earlier than occurred_at"
            });
        }
    }

    // Rule 5: Actor & Target
    total_estimated_bytes += event.producer_instance.capacity();
    if (event.producer_instance.size() > limits.max_producer_instance_length) {
        result.add_error({
            AuditValidationErrorCode::PayloadOversized,
            "producer_instance",
            "Producer instance string exceeds maximum allowed length"
        });
    }

    total_estimated_bytes += event.actor_id.capacity();
    if (!event.actor_id.empty() && event.actor_type == ActorType::Unknown) {
        result.add_error({
            AuditValidationErrorCode::MissingRequiredField,
            "actor_type",
            "Actor type must be specified when actor_id is present"
        });
    }
    if (event.actor_id.size() > limits.max_actor_id_length) {
        result.add_error({
            AuditValidationErrorCode::ActorIdOversized,
            "actor_id",
            "Actor ID exceeds maximum length of " + std::to_string(limits.max_actor_id_length)
        });
    }

    total_estimated_bytes += event.target_id.capacity();
    if (event.target_id.size() > limits.max_target_id_length) {
        result.add_error({
            AuditValidationErrorCode::TargetIdOversized,
            "target_id",
            "Target ID exceeds maximum length of " + std::to_string(limits.max_target_id_length)
        });
    }

    // Rule 6: Correlation ID & Causation ID
    total_estimated_bytes += event.correlation_id.capacity();
    if (!event.correlation_id.empty()) {
        if (event.correlation_id.size() > limits.max_correlation_id_length ||
            !is_printable_ascii_no_space(event.correlation_id)) {
            result.add_error({
                AuditValidationErrorCode::CorrelationIdInvalid,
                "correlation_id",
                "Correlation ID must be printable ASCII without spaces up to " +
                    std::to_string(limits.max_correlation_id_length) + " chars"
            });
        }
    }

    if (event.causation_id.has_value()) {
        total_estimated_bytes += event.causation_id->capacity();
        if (event.causation_id->size() > limits.max_causation_id_length ||
            !is_printable_ascii_no_space(*event.causation_id)) {
            result.add_error({
                AuditValidationErrorCode::CausationIdInvalid,
                "causation_id",
                "Causation ID must be printable ASCII without spaces up to " +
                    std::to_string(limits.max_causation_id_length) + " chars"
            });
        }
    }

    // Rule 7: Metadata limits
    if (event.metadata.size() > limits.max_metadata_entries) {
        result.add_error({
            AuditValidationErrorCode::MetadataCountExceeded,
            "metadata",
            "Metadata count (" + std::to_string(event.metadata.size()) + ") exceeds maximum limit of " +
                std::to_string(limits.max_metadata_entries)
        });
    }

    for (const auto& [key, value] : event.metadata) {
        total_estimated_bytes += key.capacity() + value.capacity();

        if (key.size() > limits.max_metadata_key_length) {
            result.add_error({
                AuditValidationErrorCode::MetadataKeyOversized,
                "metadata_key",
                "Metadata key exceeds maximum length of " + std::to_string(limits.max_metadata_key_length)
            });
        } else if (!is_valid_metadata_key(key, limits.max_metadata_key_length)) {
            result.add_error({
                AuditValidationErrorCode::MetadataKeyInvalid,
                "metadata_key",
                "Metadata key contains invalid characters (allowed: alphanumeric, '.', '_', '-')"
            });
        }

        if (value.size() > limits.max_metadata_value_length) {
            result.add_error({
                AuditValidationErrorCode::MetadataValueOversized,
                "metadata_value",
                "Metadata value exceeds maximum length of " + std::to_string(limits.max_metadata_value_length)
            });
        }
    }

    // Rule 8: Sensitive Data inspection
    auto sensitive_data_result = SensitiveDataGuard::inspect(event);
    for (const auto& err : sensitive_data_result.errors()) {
        result.add_error(err);
    }

    // Rule 9: Approximate In-Memory Size limit
    if (total_estimated_bytes > limits.max_event_size_bytes) {
        result.add_error({
            AuditValidationErrorCode::PayloadOversized,
            "audit_event",
            "Event approximate size (" + std::to_string(total_estimated_bytes) +
                " bytes) exceeds maximum limit of " + std::to_string(limits.max_event_size_bytes) + " bytes"
        });
    }

    return result;
}

} // namespace securecloud::audit::domain