#pragma once

#include "securecloud/audit/v1/audit.pb.h"

#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::files::audit {

struct ProtoValidationOutcome {
    bool valid{false};
    std::vector<std::string> error_messages;

    [[nodiscard]] std::string joined_errors() const;
};

/**
 * @brief Pimpl wrapper isolating `securecloud::audit::domain::AuditEventValidator`
 *        and `AuditEventMapper` from `src/files/` include paths.
 */
class FilesAuditProtoValidator {
  public:
    FilesAuditProtoValidator();
    ~FilesAuditProtoValidator();

    FilesAuditProtoValidator(const FilesAuditProtoValidator&) = delete;
    FilesAuditProtoValidator& operator=(const FilesAuditProtoValidator&) = delete;
    FilesAuditProtoValidator(FilesAuditProtoValidator&&) noexcept;
    FilesAuditProtoValidator& operator=(FilesAuditProtoValidator&&) noexcept;

    [[nodiscard]] ProtoValidationOutcome
    validate(const securecloud::audit::v1::AuditEventProto& proto,
             std::chrono::system_clock::time_point now = std::chrono::system_clock::now()) const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace securecloud::files::audit
