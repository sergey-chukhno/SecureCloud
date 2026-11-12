#pragma once

#include "securecloud/audit/v1/audit.grpc.pb.h"
#include "securecloud/security/mtls_config.hpp"

#include <chrono>
#include <cstdint>
#include <grpcpp/grpcpp.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::auth::audit {

struct AuthAuditClientConfig {
    std::string target_endpoint{"audit:50055"};
    std::chrono::milliseconds timeout{2000};
    common::security::SecurityCredentialsConfig tls_credentials;
    std::string expected_peer_san{"audit"};
};

struct AuditBatchSubmitResult {
    bool rpc_success{false};
    grpc::Status status;
    uint32_t accepted_count{0};
    uint32_t rejected_count{0};
    std::vector<std::string> rejected_event_ids;
};

/// Abstract interface for submitting batched audit events to AuditIngestionService.
class IAuthAuditClient {
  public:
    virtual ~IAuthAuditClient() = default;
    virtual AuditBatchSubmitResult submit_batch(const std::vector<::securecloud::audit::v1::AuditEventProto>& events) = 0;
};

/// mTLS-authenticated gRPC client for AuditIngestionService with strict deadline enforcement
/// and SAN DNS peer identity verification (`DNS:audit` / `audit.securecloud.internal`).
class AuthAuditClient final : public IAuthAuditClient {
  public:
    /// Constructs a production mTLS gRPC client. Fails closed if TLS credentials are invalid/missing.
    explicit AuthAuditClient(AuthAuditClientConfig config);

    /// Constructs a client around an injected gRPC StubInterface (for deterministic unit testing).
    AuthAuditClient(AuthAuditClientConfig config,
                    std::shared_ptr<::securecloud::audit::v1::AuditIngestionService::StubInterface> stub);

    AuditBatchSubmitResult submit_batch(const std::vector<::securecloud::audit::v1::AuditEventProto>& events) override;

  private:
    AuthAuditClientConfig config_;
    std::shared_ptr<grpc::Channel> channel_;
    std::shared_ptr<::securecloud::audit::v1::AuditIngestionService::StubInterface> stub_;
};

} // namespace securecloud::auth::audit
