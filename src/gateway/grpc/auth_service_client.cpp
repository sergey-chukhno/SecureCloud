#include "grpc/auth_service_client.hpp"

#include <grpcpp/grpcpp.h>
#include <utility>

namespace securecloud::gateway::grpc {
namespace {

DependencyError null_stub_error() {
    return DependencyError{
        .kind = DependencyErrorKind::ServiceUnavailable,
        .message = "AuthService stub is unavailable or null",
        .grpc_code = ::grpc::StatusCode::UNAVAILABLE,
    };
}

} // namespace

AuthServiceClient::AuthServiceClient(std::shared_ptr<securecloud::auth::v1::AuthService::StubInterface> stub)
    : stub_(std::move(stub)) {}

AuthServiceClient::AuthServiceClient(const std::shared_ptr<::grpc::Channel>& channel)
    : stub_(channel ? securecloud::auth::v1::AuthService::NewStub(channel) : nullptr) {}

Result<securecloud::auth::v1::AuthenticateResponse>
AuthServiceClient::authenticate(const securecloud::auth::v1::AuthenticateRequest& req, ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::auth::v1::AuthenticateResponse resp;
    auto status = stub_->Authenticate(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::auth::v1::ValidateSessionResponse>
AuthServiceClient::validate_session(const securecloud::auth::v1::ValidateSessionRequest& req, ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::auth::v1::ValidateSessionResponse resp;
    auto status = stub_->ValidateSession(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::auth::v1::RefreshSessionResponse>
AuthServiceClient::refresh_session(const securecloud::auth::v1::RefreshSessionRequest& req, ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::auth::v1::RefreshSessionResponse resp;
    auto status = stub_->RefreshSession(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::auth::v1::RevokeSessionResponse>
AuthServiceClient::revoke_session(const securecloud::auth::v1::RevokeSessionRequest& req, ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::auth::v1::RevokeSessionResponse resp;
    auto status = stub_->RevokeSession(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::auth::v1::GetUserResponse>
AuthServiceClient::get_user(const securecloud::auth::v1::GetUserRequest& req, ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::auth::v1::GetUserResponse resp;
    auto status = stub_->GetUser(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::auth::v1::RegisterDeviceResponse>
AuthServiceClient::register_device(const securecloud::auth::v1::RegisterDeviceRequest& req, ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::auth::v1::RegisterDeviceResponse resp;
    auto status = stub_->RegisterDevice(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::auth::v1::GetCryptoIdentityResponse>
AuthServiceClient::get_crypto_identity(const securecloud::auth::v1::GetCryptoIdentityRequest& req,
                                       ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::auth::v1::GetCryptoIdentityResponse resp;
    auto status = stub_->GetCryptoIdentity(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::auth::v1::GetDeviceCryptoDirectoryResponse>
AuthServiceClient::get_device_crypto_directory(const securecloud::auth::v1::GetDeviceCryptoDirectoryRequest& req,
                                               ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::auth::v1::GetDeviceCryptoDirectoryResponse resp;
    auto status = stub_->GetDeviceCryptoDirectory(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

} // namespace securecloud::gateway::grpc
