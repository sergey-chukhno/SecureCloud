#include "auth/service/auth_service_impl.hpp"

#include "securecloud/security/mtls_config.hpp"

#include <chrono>
#include <iostream>
#include <string_view>

namespace securecloud::auth::service {

// Temporary stub class definitions to satisfy std::unique_ptr<T> requirements
// until full controller/manager implementations are added.
class AuthenticationController {};
class SessionManager {};
class DeviceManager {};
class CryptoDirectoryManager {};

AuthServiceImpl::AuthServiceImpl() = default;
AuthServiceImpl::~AuthServiceImpl() = default;

std::string AuthServiceImpl::extract_client_identity(const ::grpc::ServerContext* context) const {
    if (!context || !context->auth_context()) {
        return "anonymous";
    }

    auto identity = securecloud::common::security::extract_peer_service_identity(*context->auth_context());
    return identity.value_or("unknown_peer");
}

void AuthServiceImpl::log_rpc_execution(std::string_view rpc_name, const ::grpc::ServerContext* context,
                                        const ::grpc::Status& status, std::chrono::microseconds duration) const {

    std::string client_san = extract_client_identity(context);

    std::cout << "[SecureCloud] [auth] RPC=" << rpc_name << " | PeerSAN=" << client_san
              << " | Status=" << status.error_code() << " | Duration=" << duration.count() << "us\n";
}

#define IMPLEMENT_UNIMPLEMENTED_RPC(MethodName, RequestType, ResponseType)                                      \
    ::grpc::Status AuthServiceImpl::MethodName(::grpc::ServerContext* context,                                  \
                                               const ::securecloud::auth::v1::RequestType*,                     \
                                               ::securecloud::auth::v1::ResponseType*) {                        \
        auto start = std::chrono::steady_clock::now();                                                          \
        ::grpc::Status status(::grpc::StatusCode::UNIMPLEMENTED, "RPC " #MethodName " is not implemented yet"); \
        auto duration =                                                                                         \
            std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);    \
        log_rpc_execution(#MethodName, context, status, duration);                                              \
        return status;                                                                                          \
    }

// 12 Proto RPC Implementations (matching auth.proto)
IMPLEMENT_UNIMPLEMENTED_RPC(Authenticate, AuthenticateRequest, AuthenticateResponse)
IMPLEMENT_UNIMPLEMENTED_RPC(RefreshSession, RefreshSessionRequest, RefreshSessionResponse)
IMPLEMENT_UNIMPLEMENTED_RPC(ValidateSession, ValidateSessionRequest, ValidateSessionResponse)
IMPLEMENT_UNIMPLEMENTED_RPC(RevokeSession, RevokeSessionRequest, RevokeSessionResponse)
IMPLEMENT_UNIMPLEMENTED_RPC(GetUser, GetUserRequest, GetUserResponse)
IMPLEMENT_UNIMPLEMENTED_RPC(GetDevice, GetDeviceRequest, GetDeviceResponse)
IMPLEMENT_UNIMPLEMENTED_RPC(ListUserDevices, ListUserDevicesRequest, ListUserDevicesResponse)
IMPLEMENT_UNIMPLEMENTED_RPC(RegisterDevice, RegisterDeviceRequest, RegisterDeviceResponse)
IMPLEMENT_UNIMPLEMENTED_RPC(RevokeDevice, RevokeDeviceRequest, RevokeDeviceResponse)
IMPLEMENT_UNIMPLEMENTED_RPC(GetDeviceCryptoDirectory, GetDeviceCryptoDirectoryRequest, GetDeviceCryptoDirectoryResponse)
IMPLEMENT_UNIMPLEMENTED_RPC(GetCryptoIdentity, GetCryptoIdentityRequest, GetCryptoIdentityResponse)
IMPLEMENT_UNIMPLEMENTED_RPC(UpdateCryptoPrekeys, UpdateCryptoPrekeysRequest, UpdateCryptoPrekeysResponse)

#undef IMPLEMENT_UNIMPLEMENTED_RPC

} // namespace securecloud::auth::service