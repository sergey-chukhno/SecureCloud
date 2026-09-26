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

  private:
    std::shared_ptr<securecloud::auth::v1::AuthService::StubInterface> stub_;
};

} // namespace securecloud::gateway::grpc
