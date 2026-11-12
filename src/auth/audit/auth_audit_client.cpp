#include "auth/audit/auth_audit_client.hpp"

#include <stdexcept>
#include <utility>

namespace securecloud::auth::audit {

namespace {

[[nodiscard]] bool is_authorized_audit_peer(const grpc::AuthContext& auth_ctx, std::string_view configured_san) {
    if (!configured_san.empty() && common::security::verify_peer_service_identity(auth_ctx, configured_san)) {
        return true;
    }
    return common::security::verify_peer_service_identity(auth_ctx, "audit") ||
           common::security::verify_peer_service_identity(auth_ctx, "audit.securecloud.internal");
}

} // namespace

AuthAuditClient::AuthAuditClient(AuthAuditClientConfig config) : config_(std::move(config)) {
    if (config_.target_endpoint.empty()) {
        throw std::invalid_argument("AuthAuditClient target_endpoint must not be empty");
    }
    if (config_.timeout.count() <= 0) {
        throw std::invalid_argument("AuthAuditClient timeout must be positive");
    }

    // Fail closed if CA certificate, client certificate, or client private key cannot be loaded
    auto creds = common::security::MtlsCredentialLoader::create_client_credentials(config_.tls_credentials);

    grpc::ChannelArguments channel_args;
    if (!config_.expected_peer_san.empty()) {
        channel_args.SetSslTargetNameOverride(config_.expected_peer_san);
    }

    channel_ = grpc::CreateCustomChannel(config_.target_endpoint, std::move(creds), channel_args);
    if (!channel_) {
        throw std::runtime_error("Failed to create gRPC mTLS channel to Audit Service");
    }

    stub_ = ::securecloud::audit::v1::AuditIngestionService::NewStub(channel_);
}

AuthAuditClient::AuthAuditClient(
    AuthAuditClientConfig config,
    std::shared_ptr<::securecloud::audit::v1::AuditIngestionService::StubInterface> stub)
    : config_(std::move(config)), stub_(std::move(stub)) {
    if (config_.timeout.count() <= 0) {
        throw std::invalid_argument("AuthAuditClient timeout must be positive");
    }
    if (!stub_) {
        throw std::invalid_argument("AuthAuditClient stub must not be null");
    }
}

AuditBatchSubmitResult
AuthAuditClient::submit_batch(const std::vector<::securecloud::audit::v1::AuditEventProto>& events) {
    AuditBatchSubmitResult result;
    if (events.empty()) {
        result.rpc_success = true;
        result.status = grpc::Status::OK;
        return result;
    }

    ::securecloud::audit::v1::BatchSubmitAuditEventsRequest request;
    for (const auto& ev : events) {
        *request.add_events() = ev;
    }

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + config_.timeout);

    ::securecloud::audit::v1::BatchSubmitAuditEventsResponse response;
    const grpc::Status status = stub_->BatchSubmitAuditEvents(&context, request, &response);

    if (const auto auth_ctx = context.auth_context(); auth_ctx && auth_ctx->IsPeerAuthenticated()) {
        if (!is_authorized_audit_peer(*auth_ctx, config_.expected_peer_san)) {
            result.rpc_success = false;
            result.status = grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                                         "Peer SAN DNS identity does not match Audit Service");
            return result;
        }
    }

    result.status = status;
    result.rpc_success = status.ok();
    if (status.ok()) {
        result.accepted_count = response.accepted_count();
        result.rejected_count = response.rejected_count();
        result.rejected_event_ids.reserve(static_cast<std::size_t>(response.rejected_event_ids_size()));
        for (const auto& id : response.rejected_event_ids()) {
            result.rejected_event_ids.push_back(id);
        }
    }

    return result;
}

} // namespace securecloud::auth::audit
