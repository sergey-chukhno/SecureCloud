#pragma once

#include "securecloud/audit/v1/audit.grpc.pb.h"

#include <vector>

namespace securecloud::files::audit {

/**
 * @brief Abstract interface for submitting audit event batches to securecloud-audit.
 */
class IFilesAuditClient {
  public:
    virtual ~IFilesAuditClient() = default;

    /**
     * @brief Dispatches a batch of audit events to the audit service.
     * @param events Vector of populated AuditEventProto messages.
     * @return true if accepted by Audit Service, false if error/rejection.
     */
    virtual bool submit_batch(const std::vector<securecloud::audit::v1::AuditEventProto>& events) = 0;
};

} // namespace securecloud::files::audit
