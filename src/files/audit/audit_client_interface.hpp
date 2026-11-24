#pragma once

#include "securecloud/audit/v1/audit.grpc.pb.h"

#include <cstdint>
#include <grpcpp/grpcpp.h>
#include <string>
#include <vector>

namespace securecloud::files::audit {

struct FilesAuditBatchSubmitResult {
    bool rpc_success{false};
    grpc::Status status;
    uint32_t accepted_count{0};
    uint32_t rejected_count{0};
    std::vector<std::string> rejected_event_ids;
};

/**
 * @brief Abstract interface for submitting audit event batches to securecloud-audit.
 */
class IFilesAuditClient {
  public:
    virtual ~IFilesAuditClient() = default;

    /**
     * @brief Dispatches a batch of audit events to the audit service.
     * @param events Vector of populated AuditEventProto messages (max 100 per batch).
     * @return Structured RPC and per-event ingestion result.
     */
    [[nodiscard]] virtual FilesAuditBatchSubmitResult
    submit_batch(const std::vector<securecloud::audit::v1::AuditEventProto>& events) = 0;
};

} // namespace securecloud::files::audit