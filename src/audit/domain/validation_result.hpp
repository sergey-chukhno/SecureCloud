#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace securecloud::audit::domain {

    enum class AuditValidationErrorCode {
        Success = 0,
        MissingRequiredField,
        InvalidEventId,
        EventIdNotUuidV7,
        ClockSkewFuture,
        ClockSkewTooOld,
        ReceivedAtBeforeOccurredAt,
        InvalidEventTypeFormat,
        InvalidSeverity,
        UnauthorizedProducer,
        PayloadOversized,
        MetadataCountExceeded,
        MetadataKeyInvalid,
        MetadataKeyOversized,
        MetadataValueOversized,
        ActorIdOversized,
        TargetIdOversized,
        CorrelationIdInvalid,
        CausationIdInvalid,
        SensitiveDataDetected
    };

    [[nodiscard]] std::string_view to_string(AuditValidationErrorCode code) noexcept;

    struct AuditValidationError {
        AuditValidationErrorCode code{AuditValidationErrorCode::Success};
        std::string field;
        std::string message;
    };

    class AuditValidationResult {
    public:
        [[nodiscard]] static AuditValidationResult ok() noexcept;
        [[nodiscard]] static AuditValidationResult failure(AuditValidationError error);

        void add_error(AuditValidationError error);

        [[nodiscard]] bool is_valid() const noexcept { return errors_.empty(); }
        [[nodiscard]] const std::vector<AuditValidationError>& errors() const noexcept { return errors_; }

    private:
        std::vector<AuditValidationError> errors_;
    };

} // namespace securecloud::audit::domain
