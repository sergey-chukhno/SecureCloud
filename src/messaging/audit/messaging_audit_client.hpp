#pragma once

#include "securecloud/audit/v1/audit.grpc.pb.h"

#include <chrono>
#include <grpcpp/grpcpp.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::messaging::audit {

/// Transport abstraction for dispatching Messaging audit batches to AuditIngestionService.
class IMessagingAuditClient {
  public:
    virtual ~IMessagingAuditClient() = default;

    struct BatchResult {
        bool success{false};
        bool is_transient_error{false};
        std::string error_message;
        std::vector<std::string> rejected_event_ids;
    };

    virtual BatchResult send_batch(const std::vector<securecloud::audit::v1::AuditEventProto>& events) = 0;
};

struct AuditClientConfig {
    std::string target_address{"audit:50055"};
    std::string client_cert_path{"/etc/securecloud/certs/service.crt"};
    std::string client_key_path{"/etc/securecloud/certs/service.key"};
    std::string ca_cert_path{"/etc/securecloud/certs/ca.crt"};
    std::string expected_peer_san{"audit"};
    std::chrono::milliseconds timeout{5000};

    // Optional in-memory PEM buffers (used in hermetic mTLS tests without temp files)
    std::string ca_cert_pem;
    std::string client_cert_pem;
    std::string client_key_pem;
};

/// Fail-closed mTLS gRPC client for AuditIngestionService with deadline enforcement
/// and strict peer SAN verification (`audit` / `audit.securecloud.internal`).
class MessagingAuditClient final : public IMessagingAuditClient {
  public:
    explicit MessagingAuditClient(AuditClientConfig config);

    MessagingAuditClient(AuditClientConfig config,
                         std::shared_ptr<securecloud::audit::v1::AuditIngestionService::StubInterface> stub);

    ~MessagingAuditClient() override = default;

    BatchResult send_batch(const std::vector<securecloud::audit::v1::AuditEventProto>& events) override;

    /**
     * Publishes a batch of up to 100 Audit Events via gRPC.
     * Returns true if the RPC succeeds and all events are accepted.
     */
    bool publish_batch(const std::vector<securecloud::audit::v1::AuditEventProto>& events);

  private:
    AuditClientConfig config_;
    std::shared_ptr<grpc::Channel> channel_;
    std::shared_ptr<securecloud::audit::v1::AuditIngestionService::StubInterface> stub_;
};

} // namespace securecloud::messaging::audit
