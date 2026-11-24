#pragma once

#include "files/audit/audit_client_interface.hpp"
#include "securecloud/audit/v1/audit.grpc.pb.h"
#include "securecloud/security/mtls_config.hpp"

#include <chrono>
#include <cstddef>
#include <grpcpp/grpcpp.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::files::audit {

struct GrpcAuditClientConfig {
    std::string target_endpoint{"audit:50055"};
    std::chrono::milliseconds timeout{std::chrono::milliseconds{2000}};
    common::security::SecurityCredentialsConfig tls_credentials;
    std::string expected_peer_san{"audit"};
};

/**
 * @brief Fail-closed mTLS gRPC implementation of IFilesAuditClient connecting to securecloud-audit.
 *
 * Enforces:
 * - Mandatory mTLS client credentials (no plaintext channel fallback)
 * - SSL target name override + post-RPC peer SAN DNS verification (`audit` / `audit.securecloud.internal`)
 * - Bounded batch size (<= 100 events per AUDIT-005)
 * - Strict per-RPC deadline
 */
class GrpcAuditClient final : public IFilesAuditClient {
  public:
    static constexpr std::size_t k_max_batch_size = 100;

    /// Constructs a production mTLS gRPC client. Fails closed if TLS credentials are missing or invalid.
    explicit GrpcAuditClient(GrpcAuditClientConfig config);

    /// Constructs a client around an injected gRPC StubInterface with explicit config (for unit tests).
    GrpcAuditClient(GrpcAuditClientConfig config,
                    std::shared_ptr<securecloud::audit::v1::AuditIngestionService::StubInterface> stub);

    /// Convenience unit-test constructor around an injected gRPC StubInterface.
    explicit GrpcAuditClient(std::shared_ptr<securecloud::audit::v1::AuditIngestionService::StubInterface> stub,
                             std::chrono::milliseconds timeout = std::chrono::milliseconds{2000});

    ~GrpcAuditClient() override = default;

    [[nodiscard]] FilesAuditBatchSubmitResult
    submit_batch(const std::vector<securecloud::audit::v1::AuditEventProto>& events) override;

  private:
    GrpcAuditClientConfig config_;
    std::shared_ptr<grpc::Channel> channel_;
    std::shared_ptr<securecloud::audit::v1::AuditIngestionService::StubInterface> stub_;
};

} // namespace securecloud::files::audit
