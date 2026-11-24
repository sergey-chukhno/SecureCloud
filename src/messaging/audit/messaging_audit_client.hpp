#pragma once

#include "audit/messaging_outbox_relay.hpp"
#include "securecloud/audit/v1/audit.grpc.pb.h"
#include "securecloud/security/mtls_config.hpp"

#include <chrono>
#include <grpcpp/grpcpp.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::messaging::audit {

struct AuditClientConfig {
    std::string target_address{"audit.securecloud.internal:443"};
    common::security::SecurityCredentialsConfig tls_credentials;
    std::string expected_peer_san{"audit"};
    std::chrono::milliseconds timeout{5000};
};

class MessagingAuditClient final : public IMessagingAuditClient {
  public:
    explicit MessagingAuditClient(const AuditClientConfig& config);
    ~MessagingAuditClient() = default;

    /**
     * Publishes a batch of up to 100 Audit Events via gRPC.
     * Returns true if the RPC succeeds and all events are accepted.
     */
    BatchResult send_batch(const std::vector<securecloud::audit::v1::AuditEventProto>& events) override;

  private:
    AuditClientConfig config_;
    std::unique_ptr<securecloud::audit::v1::AuditIngestionService::Stub> stub_;
    std::shared_ptr<grpc::Channel> channel_;
};

} // namespace securecloud::messaging::audit
