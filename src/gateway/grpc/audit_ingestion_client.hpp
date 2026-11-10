#pragma once

#include "grpc/audit_client_interface.hpp"

#include <grpcpp/grpcpp.h>
#include <memory>

namespace securecloud::gateway::grpc {

class AuditIngestionClient : public IAuditIngestionClient {
  public:
    explicit AuditIngestionClient(std::shared_ptr<securecloud::audit::v1::AuditIngestionService::StubInterface> stub);
    explicit AuditIngestionClient(const std::shared_ptr<::grpc::Channel>& channel);

    ~AuditIngestionClient() override = default;

    Result<securecloud::audit::v1::SubmitAuditEventResponse>
    submit_event(const securecloud::audit::v1::SubmitAuditEventRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::audit::v1::BatchSubmitAuditEventsResponse>
    batch_submit_events(const securecloud::audit::v1::BatchSubmitAuditEventsRequest& req,
                        ClientCallContext& ctx) override;

  private:
    std::shared_ptr<securecloud::audit::v1::AuditIngestionService::StubInterface> stub_;
};

} // namespace securecloud::gateway::grpc
