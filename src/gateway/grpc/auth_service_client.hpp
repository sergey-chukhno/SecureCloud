#pragma once

#include "grpc/auth_client_interface.hpp"
#include "securecloud/auth/v1/auth.grpc.pb.h"

#include <grpcpp/grpcpp.h>
#include <memory>

namespace securecloud::gateway::grpc {

class AuthServiceClient : public IAuthClient {
  public:
    explicit AuthServiceClient(std::shared_ptr<securecloud::auth::v1::AuthService::StubInterface> stub);
    explicit AuthServiceClient(const std::shared_ptr<::grpc::Channel>& channel);

    ~AuthServiceClient() override = default;

    Result<securecloud::auth::v1::AuthenticateResponse>
    authenticate(const securecloud::auth::v1::AuthenticateRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::auth::v1::ValidateSessionResponse>
    validate_session(const securecloud::auth::v1::ValidateSessionRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::auth::v1::RefreshSessionResponse>
    refresh_session(const securecloud::auth::v1::RefreshSessionRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::auth::v1::RevokeSessionResponse>
    revoke_session(const securecloud::auth::v1::RevokeSessionRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::auth::v1::GetUserResponse> get_user(const securecloud::auth::v1::GetUserRequest& req,
                                                            ClientCallContext& ctx) override;

    Result<securecloud::auth::v1::RegisterDeviceResponse>
    register_device(const securecloud::auth::v1::RegisterDeviceRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::auth::v1::GetCryptoIdentityResponse>
    get_crypto_identity(const securecloud::auth::v1::GetCryptoIdentityRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::auth::v1::GetDeviceCryptoDirectoryResponse>
    get_device_crypto_directory(const securecloud::auth::v1::GetDeviceCryptoDirectoryRequest& req,
                                ClientCallContext& ctx) override;

    Result<securecloud::auth::v1::UpdateCryptoPrekeysResponse>
    update_crypto_prekeys(const securecloud::auth::v1::UpdateCryptoPrekeysRequest& req,
                          ClientCallContext& ctx) override;

    Result<securecloud::auth::v1::GetPrekeyInventoryStatusResponse>
    get_prekey_inventory_status(const securecloud::auth::v1::GetPrekeyInventoryStatusRequest& req,
                                ClientCallContext& ctx) override;

    Result<securecloud::auth::v1::ClaimPrekeyBundleResponse>
    claim_prekey_bundle(const securecloud::auth::v1::ClaimPrekeyBundleRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::auth::v1::GetPublicSigningKeyResponse>
    get_public_signing_key(const securecloud::auth::v1::GetPublicSigningKeyRequest& req,
                           ClientCallContext& ctx) override;

    Result<securecloud::auth::v1::InitiateMfaEnrollmentResponse>
    initiate_mfa_enrollment(const securecloud::auth::v1::InitiateMfaEnrollmentRequest& req,
                            ClientCallContext& ctx) override;

    Result<securecloud::auth::v1::ConfirmMfaEnrollmentResponse>
    confirm_mfa_enrollment(const securecloud::auth::v1::ConfirmMfaEnrollmentRequest& req,
                           ClientCallContext& ctx) override;

    Result<securecloud::auth::v1::VerifyMfaChallengeResponse>
    verify_mfa_challenge(const securecloud::auth::v1::VerifyMfaChallengeRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::auth::v1::DisableMfaResponse> disable_mfa(const securecloud::auth::v1::DisableMfaRequest& req,
                                                                  ClientCallContext& ctx) override;

    Result<securecloud::auth::v1::GetDeviceResponse> get_device(const securecloud::auth::v1::GetDeviceRequest& req,
                                                                ClientCallContext& ctx) override;

    Result<securecloud::auth::v1::ListUserDevicesResponse>
    list_user_devices(const securecloud::auth::v1::ListUserDevicesRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::auth::v1::InitiateDevicePairingResponse>
    initiate_device_pairing(const securecloud::auth::v1::InitiateDevicePairingRequest& req,
                            ClientCallContext& ctx) override;

    Result<securecloud::auth::v1::AuthorizeDeviceResponse>
    authorize_device(const securecloud::auth::v1::AuthorizeDeviceRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::auth::v1::RevokeDeviceResponse>
    revoke_device(const securecloud::auth::v1::RevokeDeviceRequest& req, ClientCallContext& ctx) override;

  private:
    std::shared_ptr<securecloud::auth::v1::AuthService::StubInterface> stub_;
};

} // namespace securecloud::gateway::grpc
