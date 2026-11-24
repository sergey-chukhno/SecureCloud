#include "messaging_audit_client.hpp"

#include <stdexcept>

namespace securecloud::messaging::audit {

MessagingAuditClient::MessagingAuditClient(const AuditClientConfig& config) : config_(config) {
    auto credentials = common::security::MtlsCredentialLoader::create_client_credentials(config.tls_credentials);
    if (!credentials) {
        throw std::runtime_error("Failed to create mTLS credentials for Messaging Audit client");
    }

    grpc::ChannelArguments channel_args;
    if (!config.expected_peer_san.empty()) {
        channel_args.SetSslTargetNameOverride(config.expected_peer_san);
    }

    channel_ = grpc::CreateCustomChannel(config.target_address, std::move(credentials), channel_args);
    stub_ = securecloud::audit::v1::AuditIngestionService::NewStub(channel_);
}

MessagingAuditClient::BatchResult
MessagingAuditClient::send_batch(const std::vector<securecloud::audit::v1::AuditEventProto>& events) {
    BatchResult result;
    if (events.empty()) {
        result.success = true;
        return result;
    }

    securecloud::audit::v1::BatchSubmitAuditEventsRequest request;
    for (const auto& ev : events) {
        *request.add_events() = ev;
    }

    securecloud::audit::v1::BatchSubmitAuditEventsResponse response;
    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + config_.timeout);

    grpc::Status status = stub_->BatchSubmitAuditEvents(&context, request, &response);

    if (const auto auth_ctx = context.auth_context(); auth_ctx && auth_ctx->IsPeerAuthenticated()) {
        if (!common::security::verify_peer_service_identity(*auth_ctx, config_.expected_peer_san)) {
            result.error_message = "Audit peer SAN identity mismatch";
            result.is_transient_error = false;
            return result;
        }
    }

    if (!status.ok()) {
        result.error_message = status.error_message();
        result.is_transient_error = status.error_code() == grpc::StatusCode::UNAVAILABLE ||
                                    status.error_code() == grpc::StatusCode::DEADLINE_EXCEEDED ||
                                    status.error_code() == grpc::StatusCode::RESOURCE_EXHAUSTED ||
                                    status.error_code() == grpc::StatusCode::ABORTED;
        return result;
    }

    result.rejected_event_ids.assign(response.rejected_event_ids().begin(), response.rejected_event_ids().end());
    result.success = response.rejected_count() == 0;
    if (!result.success) {
        result.error_message = "Audit service rejected one or more Messaging events";
    }
    return result;
}

} // namespace securecloud::messaging::audit
