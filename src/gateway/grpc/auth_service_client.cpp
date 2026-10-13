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

Result<securecloud::auth::v1::UpdateCryptoPrekeysResponse>
AuthServiceClient::update_crypto_prekeys(const securecloud::auth::v1::UpdateCryptoPrekeysRequest& req,
                                         ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::auth::v1::UpdateCryptoPrekeysResponse resp;
    auto status = stub_->UpdateCryptoPrekeys(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::auth::v1::GetPrekeyInventoryStatusResponse>
AuthServiceClient::get_prekey_inventory_status(const securecloud::auth::v1::GetPrekeyInventoryStatusRequest& req,
                                               ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::auth::v1::GetPrekeyInventoryStatusResponse resp;
    auto status = stub_->GetPrekeyInventoryStatus(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::auth::v1::ClaimPrekeyBundleResponse>
AuthServiceClient::claim_prekey_bundle(const securecloud::auth::v1::ClaimPrekeyBundleRequest& req,
                                       ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::auth::v1::ClaimPrekeyBundleResponse resp;
    auto status = stub_->ClaimPrekeyBundle(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::auth::v1::GetPublicSigningKeyResponse>
AuthServiceClient::get_public_signing_key(const securecloud::auth::v1::GetPublicSigningKeyRequest& req,
                                          ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::auth::v1::GetPublicSigningKeyResponse resp;
    auto status = stub_->GetPublicSigningKey(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::auth::v1::InitiateMfaEnrollmentResponse>
AuthServiceClient::initiate_mfa_enrollment(const securecloud::auth::v1::InitiateMfaEnrollmentRequest& req,
                                           ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::auth::v1::InitiateMfaEnrollmentResponse resp;
    auto status = stub_->InitiateMfaEnrollment(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::auth::v1::ConfirmMfaEnrollmentResponse>
AuthServiceClient::confirm_mfa_enrollment(const securecloud::auth::v1::ConfirmMfaEnrollmentRequest& req,
                                          ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::auth::v1::ConfirmMfaEnrollmentResponse resp;
    auto status = stub_->ConfirmMfaEnrollment(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::auth::v1::VerifyMfaChallengeResponse>
AuthServiceClient::verify_mfa_challenge(const securecloud::auth::v1::VerifyMfaChallengeRequest& req,
                                        ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::auth::v1::VerifyMfaChallengeResponse resp;
    auto status = stub_->VerifyMfaChallenge(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::auth::v1::DisableMfaResponse>
AuthServiceClient::disable_mfa(const securecloud::auth::v1::DisableMfaRequest& req, ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::auth::v1::DisableMfaResponse resp;
    auto status = stub_->DisableMfa(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::auth::v1::GetDeviceResponse>
AuthServiceClient::get_device(const securecloud::auth::v1::GetDeviceRequest& req, ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::auth::v1::GetDeviceResponse resp;
    auto status = stub_->GetDevice(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::auth::v1::ListUserDevicesResponse>
AuthServiceClient::list_user_devices(const securecloud::auth::v1::ListUserDevicesRequest& req, ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::auth::v1::ListUserDevicesResponse resp;
    auto status = stub_->ListUserDevices(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::auth::v1::InitiateDevicePairingResponse>
AuthServiceClient::initiate_device_pairing(const securecloud::auth::v1::InitiateDevicePairingRequest& req,
                                           ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::auth::v1::InitiateDevicePairingResponse resp;
    auto status = stub_->InitiateDevicePairing(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::auth::v1::AuthorizeDeviceResponse>
AuthServiceClient::authorize_device(const securecloud::auth::v1::AuthorizeDeviceRequest& req, ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::auth::v1::AuthorizeDeviceResponse resp;
    auto status = stub_->AuthorizeDevice(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::auth::v1::RevokeDeviceResponse>
AuthServiceClient::revoke_device(const securecloud::auth::v1::RevokeDeviceRequest& req, ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::auth::v1::RevokeDeviceResponse resp;
    auto status = stub_->RevokeDevice(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

} // namespace securecloud::gateway::grpc
