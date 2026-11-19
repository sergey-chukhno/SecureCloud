#pragma once

#include "securecloud/audit/v1/audit.grpc.pb.h"

#include <grpcpp/grpcpp.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::messaging::audit {

struct AuditClientConfig {
    std::string target_address{"audit.securecloud.internal:443"};
    std::string client_cert_path{"/etc/securecloud/certs/messaging/client.crt"};
    std::string client_key_path{"/etc/securecloud/certs/messaging/client.key"};
    std::string ca_cert_path{"/etc/securecloud/certs/ca-trust.pem"};
    std::string expected_peer_san{"audit.securecloud.internal"};
};

class MessagingAuditClient {
  public:
    explicit MessagingAuditClient(const AuditClientConfig& config);
    ~MessagingAuditClient() = default;

    /**
     * Publishes a batch of up to 100 Audit Events via gRPC.
     * Returns true if the RPC succeeds and all events are accepted.
     */
    bool publish_batch(const std::vector<securecloud::audit::v1::AuditEventProto>& events);

  private:
    std::unique_ptr<securecloud::audit::v1::AuditIngestionService::Stub> stub_;
    std::shared_ptr<grpc::Channel> channel_;
};

} // namespace securecloud::messaging::audit
