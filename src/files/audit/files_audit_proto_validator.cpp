#include "files/audit/files_audit_proto_validator.hpp"

#include "domain/audit_event_mapper.hpp"
#include "domain/audit_event_validator.hpp"

#include <sstream>

namespace securecloud::files::audit {

struct FilesAuditProtoValidator::Impl {
    securecloud::audit::domain::AuditEventValidationLimits limits{};
};

std::string ProtoValidationOutcome::joined_errors() const {
    if (error_messages.empty()) {
        return {};
    }
    std::ostringstream oss;
    for (std::size_t i = 0; i < error_messages.size(); ++i) {
        if (i > 0) {
            oss << "; ";
        }
        oss << error_messages[i];
    }
    return oss.str();
}

FilesAuditProtoValidator::FilesAuditProtoValidator() : impl_(std::make_unique<Impl>()) {}
FilesAuditProtoValidator::~FilesAuditProtoValidator() = default;
FilesAuditProtoValidator::FilesAuditProtoValidator(FilesAuditProtoValidator&&) noexcept = default;
FilesAuditProtoValidator& FilesAuditProtoValidator::operator=(FilesAuditProtoValidator&&) noexcept = default;

ProtoValidationOutcome FilesAuditProtoValidator::validate(const securecloud::audit::v1::AuditEventProto& proto,
                                                          std::chrono::system_clock::time_point now) const {
    ProtoValidationOutcome outcome;

    if (proto.producer_service() != securecloud::audit::v1::PRODUCER_SERVICE_FILES) {
        outcome.error_messages.emplace_back("producer_service: expected PRODUCER_SERVICE_FILES");
    }
    if (proto.severity() == securecloud::audit::v1::SEVERITY_UNSPECIFIED) {
        outcome.error_messages.emplace_back("severity: must not be SEVERITY_UNSPECIFIED");
    }
    if (proto.actor_type() == securecloud::audit::v1::ACTOR_TYPE_UNSPECIFIED) {
        outcome.error_messages.emplace_back("actor_type: must not be ACTOR_TYPE_UNSPECIFIED");
    }
    if (proto.target_type() == securecloud::audit::v1::TARGET_TYPE_UNSPECIFIED) {
        outcome.error_messages.emplace_back("target_type: must not be TARGET_TYPE_UNSPECIFIED");
    }

    const auto domain_event = securecloud::audit::domain::AuditEventMapper::to_domain(proto, now);
    const auto domain_res = securecloud::audit::domain::AuditEventValidator::validate(domain_event, impl_->limits, now);

    for (const auto& err : domain_res.errors()) {
        outcome.error_messages.push_back(err.field + ": " + err.message);
    }

    outcome.valid = outcome.error_messages.empty();
    return outcome;
}

} // namespace securecloud::files::audit
