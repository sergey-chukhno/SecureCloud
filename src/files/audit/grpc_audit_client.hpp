#pragma once

#include "files/audit/audit_client_interface.hpp"
#include "securecloud/audit/v1/audit.grpc.pb.h"

#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::files::audit {

struct GrpcAuditClientConfig {
    std::string target_endpoint{"127.0.0.1:50054"};
    std::string ca_cert_path;
    std::string client_cert_path;
    std::string client_key_path;
    std::chrono::milliseconds timeout{5000};
    bool use_tls{false};
};

/**
 * @brief Production gRPC implementation of IFilesAuditClient connecting to securecloud-audit.
 */
class GrpcAuditClient : public IFilesAuditClient {
  public:
    explicit GrpcAuditClient(std::shared_ptr<securecloud::audit::v1::AuditIngestionService::StubInterface> stub,
                             std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));

    explicit GrpcAuditClient(const GrpcAuditClientConfig& config);
    ~GrpcAuditClient() override = default;

    bool submit_batch(const std::vector<securecloud::audit::v1::AuditEventProto>& events) override;

  private:
    std::shared_ptr<securecloud::audit::v1::AuditIngestionService::StubInterface> stub_;
    std::chrono::milliseconds timeout_;
};

} // namespace securecloud::files::audit
