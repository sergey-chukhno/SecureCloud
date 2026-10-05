#pragma once

#include "grpc/client_call_context.hpp"
#include "grpc/dependency_error.hpp"
#include "securecloud/auth/v1/auth.pb.h"

namespace securecloud::gateway::grpc {

class IAuthClient {
  public:
    virtual ~IAuthClient() = default;

    virtual Result<securecloud::auth::v1::AuthenticateResponse>
    authenticate(const securecloud::auth::v1::AuthenticateRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::auth::v1::ValidateSessionResponse>
    validate_session(const securecloud::auth::v1::ValidateSessionRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::auth::v1::RefreshSessionResponse>
    refresh_session(const securecloud::auth::v1::RefreshSessionRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::auth::v1::RevokeSessionResponse>
    revoke_session(const securecloud::auth::v1::RevokeSessionRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::auth::v1::GetUserResponse> get_user(const securecloud::auth::v1::GetUserRequest& req,
                                                                    ClientCallContext& ctx) = 0;

    virtual Result<securecloud::auth::v1::RegisterDeviceResponse>
    register_device(const securecloud::auth::v1::RegisterDeviceRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::auth::v1::GetCryptoIdentityResponse>
    get_crypto_identity(const securecloud::auth::v1::GetCryptoIdentityRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::auth::v1::GetDeviceCryptoDirectoryResponse>
    get_device_crypto_directory(const securecloud::auth::v1::GetDeviceCryptoDirectoryRequest& req,
                                ClientCallContext& ctx) = 0;
};

} // namespace securecloud::gateway::grpc
