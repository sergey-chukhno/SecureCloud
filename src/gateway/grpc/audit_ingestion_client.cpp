#include "grpc/audit_ingestion_client.hpp"

namespace securecloud::gateway::grpc {

AuditIngestionClient::AuditIngestionClient(
    std::shared_ptr<securecloud::audit::v1::AuditIngestionService::StubInterface> stub)
    : stub_(std::move(stub)) {}

AuditIngestionClient::AuditIngestionClient(const std::shared_ptr<::grpc::Channel>& channel)
    : stub_(securecloud::audit::v1::AuditIngestionService::NewStub(channel)) {}

Result<securecloud::audit::v1::SubmitAuditEventResponse>
AuditIngestionClient::submit_event(const securecloud::audit::v1::SubmitAuditEventRequest& req, ClientCallContext& ctx) {
    securecloud::audit::v1::SubmitAuditEventResponse resp;

    const auto status = stub_->SubmitAuditEvent(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::audit::v1::BatchSubmitAuditEventsResponse>
AuditIngestionClient::batch_submit_events(const securecloud::audit::v1::BatchSubmitAuditEventsRequest& req,
                                          ClientCallContext& ctx) {
    securecloud::audit::v1::BatchSubmitAuditEventsResponse resp;

    const auto status = stub_->BatchSubmitAuditEvents(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

} // namespace securecloud::gateway::grpc
