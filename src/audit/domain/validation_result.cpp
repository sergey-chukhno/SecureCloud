#include "validation_result.hpp"

namespace securecloud::audit::domain {

std::string_view to_string(AuditValidationErrorCode code) noexcept {
    switch (code) {
    case AuditValidationErrorCode::Success:
        return "Success";
    case AuditValidationErrorCode::MissingRequiredField:
        return "MissingRequiredField";
    case AuditValidationErrorCode::InvalidEventId:
        return "InvalidEventId";
    case AuditValidationErrorCode::EventIdNotUuidV7:
        return "EventIdNotUuidV7";
    case AuditValidationErrorCode::ClockSkewFuture:
        return "ClockSkewFuture";
    case AuditValidationErrorCode::ClockSkewTooOld:
        return "ClockSkewTooOld";
    case AuditValidationErrorCode::ReceivedAtBeforeOccurredAt:
        return "ReceivedAtBeforeOccurredAt";
    case AuditValidationErrorCode::InvalidEventTypeFormat:
        return "InvalidEventTypeFormat";
    case AuditValidationErrorCode::InvalidSeverity:
        return "InvalidSeverity";
    case AuditValidationErrorCode::UnauthorizedProducer:
        return "UnauthorizedProducer";
    case AuditValidationErrorCode::PayloadOversized:
        return "PayloadOversized";
    case AuditValidationErrorCode::MetadataCountExceeded:
        return "MetadataCountExceeded";
    case AuditValidationErrorCode::MetadataKeyInvalid:
        return "MetadataKeyInvalid";
    case AuditValidationErrorCode::MetadataKeyOversized:
        return "MetadataKeyOversized";
    case AuditValidationErrorCode::MetadataValueOversized:
        return "MetadataValueOversized";
    case AuditValidationErrorCode::ActorIdOversized:
        return "ActorIdOversized";
    case AuditValidationErrorCode::TargetIdOversized:
        return "TargetIdOversized";
    case AuditValidationErrorCode::CorrelationIdInvalid:
        return "CorrelationIdInvalid";
    case AuditValidationErrorCode::CausationIdInvalid:
        return "CausationIdInvalid";
    case AuditValidationErrorCode::SensitiveDataDetected:
        return "SensitiveDataDetected";
    }
    return "UnknownError";
}

AuditValidationResult AuditValidationResult::ok() noexcept {
    return AuditValidationResult{};
}

AuditValidationResult AuditValidationResult::failure(AuditValidationError error) {
    AuditValidationResult res;
    res.add_error(std::move(error));
    return res;
}

void AuditValidationResult::add_error(AuditValidationError error) {
    errors_.push_back(std::move(error));
}

} // namespace securecloud::audit::domain