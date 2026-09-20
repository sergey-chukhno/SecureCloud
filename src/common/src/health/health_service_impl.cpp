#include "securecloud/health/health_service_impl.hpp"

#include "securecloud/security/mtls_config.hpp"

#include <utility>

namespace securecloud::common::health {

HealthServiceImpl::HealthServiceImpl(std::string service_name, HealthStatusManager& status_manager,
                                     std::string expected_client_identity)
    : service_name_(std::move(service_name)), status_manager_(status_manager),
      expected_client_identity_(std::move(expected_client_identity)) {}

const std::string& HealthServiceImpl::service_name() const noexcept {
    return service_name_;
}

const std::string& HealthServiceImpl::expected_client_identity() const noexcept {
    return expected_client_identity_;
}

void HealthServiceImpl::set_expected_client_identity(std::string expected_client_identity) {
    expected_client_identity_ = std::move(expected_client_identity);
}

grpc::Status HealthServiceImpl::Check(grpc::ServerContext* context,
                                      const securecloud::common::v1::HealthCheckRequest* request,
                                      securecloud::common::v1::HealthCheckResponse* response) {
    const grpc::AuthContext* auth_ctx = (context != nullptr) ? context->auth_context().get() : nullptr;
    return Check(auth_ctx, request, response);
}

grpc::Status HealthServiceImpl::Check(const grpc::AuthContext* auth_ctx,
                                      const securecloud::common::v1::HealthCheckRequest* request,
                                      securecloud::common::v1::HealthCheckResponse* response) {
    if (auth_ctx == nullptr || !auth_ctx->IsPeerAuthenticated()) {
        return {grpc::StatusCode::UNAUTHENTICATED, "Peer unauthenticated"};
    }

    if (!expected_client_identity_.empty()) {
        if (!security::verify_peer_service_identity(*auth_ctx, expected_client_identity_)) {
            return {grpc::StatusCode::UNAUTHENTICATED, "Peer service identity mismatch"};
        }
    }

    if (!request || !response) {
        return {grpc::StatusCode::INVALID_ARGUMENT, "Invalid request or response pointer"};
    }

    const std::string& requested_service = request->service();

    // SecureCloud Liveness Convention: empty string or canonical service name
    if (requested_service.empty() || requested_service == service_name_) {
        if (status_manager_.is_live()) {
            response->set_status(securecloud::common::v1::HealthCheckResponse::SERVING);
        } else {
            response->set_status(securecloud::common::v1::HealthCheckResponse::NOT_SERVING);
        }
        return grpc::Status::OK;
    }

    // SecureCloud Readiness Convention: "readiness"
    if (requested_service == "readiness") {
        if (status_manager_.evaluate_readiness()) {
            response->set_status(securecloud::common::v1::HealthCheckResponse::SERVING);
        } else {
            response->set_status(securecloud::common::v1::HealthCheckResponse::NOT_SERVING);
        }
        return grpc::Status::OK;
    }

    // Unrecognized service string
    response->set_status(securecloud::common::v1::HealthCheckResponse::SERVICE_UNKNOWN);
    return grpc::Status::OK;
}

} // namespace securecloud::common::health
