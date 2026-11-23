#include "messaging_audit_client.hpp"

#include "securecloud/security/mtls_config.hpp"
#include "util/zero_plaintext_guard.hpp"

#include <stdexcept>
#include <string_view>
#include <utility>

namespace securecloud::messaging::audit {

namespace {

[[nodiscard]] bool is_transient_grpc_code(grpc::StatusCode code) noexcept {
    switch (code) {
    case grpc::StatusCode::UNAVAILABLE:
    case grpc::StatusCode::DEADLINE_EXCEEDED:
    case grpc::StatusCode::RESOURCE_EXHAUSTED:
    case grpc::StatusCode::ABORTED:
    case grpc::StatusCode::INTERNAL:
    case grpc::StatusCode::UNKNOWN:
        return true;
    default:
        return false;
    }
}

[[nodiscard]] std::string_view grpc_status_name(grpc::StatusCode code) noexcept {
    switch (code) {
    case grpc::StatusCode::CANCELLED:
        return "CANCELLED";
    case grpc::StatusCode::UNKNOWN:
        return "UNKNOWN";
    case grpc::StatusCode::INVALID_ARGUMENT:
        return "INVALID_ARGUMENT";
    case grpc::StatusCode::DEADLINE_EXCEEDED:
        return "DEADLINE_EXCEEDED";
    case grpc::StatusCode::NOT_FOUND:
        return "NOT_FOUND";
    case grpc::StatusCode::ALREADY_EXISTS:
        return "ALREADY_EXISTS";
    case grpc::StatusCode::PERMISSION_DENIED:
        return "PERMISSION_DENIED";
    case grpc::StatusCode::RESOURCE_EXHAUSTED:
        return "RESOURCE_EXHAUSTED";
    case grpc::StatusCode::FAILED_PRECONDITION:
        return "FAILED_PRECONDITION";
    case grpc::StatusCode::ABORTED:
        return "ABORTED";
    case grpc::StatusCode::OUT_OF_RANGE:
        return "OUT_OF_RANGE";
    case grpc::StatusCode::UNIMPLEMENTED:
        return "UNIMPLEMENTED";
    case grpc::StatusCode::INTERNAL:
        return "INTERNAL";
    case grpc::StatusCode::UNAVAILABLE:
        return "UNAVAILABLE";
    case grpc::StatusCode::DATA_LOSS:
        return "DATA_LOSS";
    case grpc::StatusCode::UNAUTHENTICATED:
        return "UNAUTHENTICATED";
    default:
        return "ERROR";
    }
}

[[nodiscard]] bool is_authorized_audit_peer(const grpc::AuthContext& auth_ctx, std::string_view configured_san) {
    if (!configured_san.empty() && common::security::verify_peer_service_identity(auth_ctx, configured_san)) {
        return true;
    }
    return common::security::verify_peer_service_identity(auth_ctx, "audit") ||
           common::security::verify_peer_service_identity(auth_ctx, "audit.securecloud.internal");
}

} // namespace

MessagingAuditClient::MessagingAuditClient(AuditClientConfig config) : config_(std::move(config)) {
    if (config_.target_address.empty()) {
        throw std::invalid_argument("MessagingAuditClient target_address must not be empty");
    }
    if (config_.timeout.count() <= 0) {
        throw std::invalid_argument("MessagingAuditClient timeout must be positive");
    }

    grpc::SslCredentialsOptions ssl_opts;
    const bool has_any_inline_pem =
        !config_.ca_cert_pem.empty() || !config_.client_cert_pem.empty() || !config_.client_key_pem.empty();
    if (has_any_inline_pem) {
        if (config_.ca_cert_pem.empty() || config_.client_cert_pem.empty() || config_.client_key_pem.empty()) {
            throw std::runtime_error("MessagingAuditClient inline PEM bundle requires CA, client cert, and key");
        }
        ssl_opts.pem_root_certs = config_.ca_cert_pem;
        ssl_opts.pem_cert_chain = config_.client_cert_pem;
        ssl_opts.pem_private_key = config_.client_key_pem;
    } else {
        auto loaded = common::security::MtlsCredentialLoader::load_credentials_or_throw(
            {config_.ca_cert_path, config_.client_cert_path, config_.client_key_path});
        ssl_opts.pem_root_certs = std::move(loaded.ca_cert_pem);
        ssl_opts.pem_cert_chain = std::move(loaded.service_cert_pem);
        ssl_opts.pem_private_key = std::move(loaded.service_key_pem);
    }

    auto credentials = grpc::SslCredentials(ssl_opts);
    if (!credentials) {
        throw std::runtime_error("MessagingAuditClient failed to create gRPC SslCredentials");
    }

    grpc::ChannelArguments channel_args;
    if (!config_.expected_peer_san.empty()) {
        channel_args.SetSslTargetNameOverride(config_.expected_peer_san);
    }

    channel_ = grpc::CreateCustomChannel(config_.target_address, std::move(credentials), channel_args);
    if (!channel_) {
        throw std::runtime_error("MessagingAuditClient failed to create gRPC mTLS channel");
    }
    stub_ = securecloud::audit::v1::AuditIngestionService::NewStub(channel_);
}

MessagingAuditClient::MessagingAuditClient(
    AuditClientConfig config, std::shared_ptr<securecloud::audit::v1::AuditIngestionService::StubInterface> stub)
    : config_(std::move(config)), stub_(std::move(stub)) {
    if (config_.timeout.count() <= 0) {
        throw std::invalid_argument("MessagingAuditClient timeout must be positive");
    }
    if (!stub_) {
        throw std::invalid_argument("MessagingAuditClient stub must not be null");
    }
}

IMessagingAuditClient::BatchResult
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

    const grpc::Status status = stub_->BatchSubmitAuditEvents(&context, request, &response);

    if (const auto auth_ctx = context.auth_context(); auth_ctx && auth_ctx->IsPeerAuthenticated()) {
        if (!is_authorized_audit_peer(*auth_ctx, config_.expected_peer_san)) {
            result.success = false;
            result.is_transient_error = false;
            result.error_message = "UNAUTHENTICATED: Peer SAN DNS identity does not match Audit Service";
            return result;
        }
    }

    if (!status.ok()) {
        result.success = false;
        result.is_transient_error = is_transient_grpc_code(status.error_code());
        result.error_message = std::string(grpc_status_name(status.error_code())) + ": " +
                               util::ZeroPlaintextGuard::sanitize_error_message(status.error_message());
        return result;
    }

    if (response.rejected_count() > 0 || !response.rejected_event_ids().empty()) {
        result.success = false;
        result.is_transient_error = false;
        result.error_message = "INVALID_ARGUMENT: partial batch rejection";
        result.rejected_event_ids.reserve(static_cast<size_t>(response.rejected_event_ids_size()));
        for (const auto& id : response.rejected_event_ids()) {
            result.rejected_event_ids.push_back(id);
        }
        return result;
    }

    result.success = true;
    return result;
}

bool MessagingAuditClient::publish_batch(const std::vector<securecloud::audit::v1::AuditEventProto>& events) {
    return send_batch(events).success;
}

} // namespace securecloud::messaging::audit
