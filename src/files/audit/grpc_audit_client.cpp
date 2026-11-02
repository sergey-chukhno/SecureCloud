#include "files/audit/grpc_audit_client.hpp"

#include <fstream>
#include <securecloud/security/mtls_config.hpp>
#include <sstream>

namespace securecloud::files::audit {

namespace {

std::shared_ptr<::grpc::Channel> create_channel(const GrpcAuditClientConfig& config) {
    if (config.use_tls) {
        common::security::SecurityCredentialsConfig creds_cfg{
            .ca_cert_path = config.ca_cert_path,
            .service_cert_path = config.client_cert_path,
            .service_key_path = config.client_key_path,
        };
        auto creds = common::security::MtlsCredentialLoader::create_client_credentials(creds_cfg);
        ::grpc::ChannelArguments args;
        return ::grpc::CreateCustomChannel(config.target_endpoint, creds, args);
    }
    return ::grpc::CreateChannel(config.target_endpoint, ::grpc::InsecureChannelCredentials());
}

} // namespace

GrpcAuditClient::GrpcAuditClient(std::shared_ptr<securecloud::audit::v1::AuditIngestionService::StubInterface> stub,
                                 std::chrono::milliseconds timeout)
    : stub_(std::move(stub)), timeout_(timeout) {}

GrpcAuditClient::GrpcAuditClient(const GrpcAuditClientConfig& config)
    : stub_(securecloud::audit::v1::AuditIngestionService::NewStub(create_channel(config))), timeout_(config.timeout) {}

bool GrpcAuditClient::submit_batch(const std::vector<securecloud::audit::v1::AuditEventProto>& events) {
    if (events.empty()) {
        return true;
    }
    if (!stub_) {
        return false;
    }

    securecloud::audit::v1::BatchSubmitAuditEventsRequest request;
    for (const auto& ev : events) {
        *request.add_events() = ev;
    }

    securecloud::audit::v1::BatchSubmitAuditEventsResponse response;
    ::grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + timeout_);

    auto status = stub_->BatchSubmitAuditEvents(&context, request, &response);
    if (!status.ok()) {
        return false;
    }

    return response.rejected_count() == 0;
}

} // namespace securecloud::files::audit
