#pragma once

#include "securecloud/auth/v1/auth.grpc.pb.h"

#include <chrono>
#include <grpcpp/grpcpp.h>
#include <memory>
#include <string>
#include <string_view>

namespace securecloud::auth::service {

// Forward declarations of modular sub-components
class AuthenticationController;
class SessionManager;
class DeviceManager;
class CryptoDirectoryManager;

/// Implementation of the securecloud.auth.v1.AuthService gRPC interface.
class AuthServiceImpl final : public securecloud::auth::v1::AuthService::Service {
  public:
    AuthServiceImpl();
    ~AuthServiceImpl() override;

    AuthServiceImpl(const AuthServiceImpl&) = delete;
    AuthServiceImpl& operator=(const AuthServiceImpl&) = delete;
    AuthServiceImpl(AuthServiceImpl&&) = delete;
    AuthServiceImpl& operator=(AuthServiceImpl&&) = delete;

    // --- 12 Proto RPC Implementations (matching auth.proto) ---

    ::grpc::Status Authenticate(::grpc::ServerContext* context,
                                const ::securecloud::auth::v1::AuthenticateRequest* request,
                                ::securecloud::auth::v1::AuthenticateResponse* response) override;

    ::grpc::Status RefreshSession(::grpc::ServerContext* context,
                                  const ::securecloud::auth::v1::RefreshSessionRequest* request,
                                  ::securecloud::auth::v1::RefreshSessionResponse* response) override;

    ::grpc::Status ValidateSession(::grpc::ServerContext* context,
                                   const ::securecloud::auth::v1::ValidateSessionRequest* request,
                                   ::securecloud::auth::v1::ValidateSessionResponse* response) override;

    ::grpc::Status RevokeSession(::grpc::ServerContext* context,
                                 const ::securecloud::auth::v1::RevokeSessionRequest* request,
                                 ::securecloud::auth::v1::RevokeSessionResponse* response) override;

    ::grpc::Status GetUser(::grpc::ServerContext* context, const ::securecloud::auth::v1::GetUserRequest* request,
                           ::securecloud::auth::v1::GetUserResponse* response) override;

    ::grpc::Status GetDevice(::grpc::ServerContext* context, const ::securecloud::auth::v1::GetDeviceRequest* request,
                             ::securecloud::auth::v1::GetDeviceResponse* response) override;

    ::grpc::Status ListUserDevices(::grpc::ServerContext* context,
                                   const ::securecloud::auth::v1::ListUserDevicesRequest* request,
                                   ::securecloud::auth::v1::ListUserDevicesResponse* response) override;

    ::grpc::Status RegisterDevice(::grpc::ServerContext* context,
                                  const ::securecloud::auth::v1::RegisterDeviceRequest* request,
                                  ::securecloud::auth::v1::RegisterDeviceResponse* response) override;

    ::grpc::Status RevokeDevice(::grpc::ServerContext* context,
                                const ::securecloud::auth::v1::RevokeDeviceRequest* request,
                                ::securecloud::auth::v1::RevokeDeviceResponse* response) override;

    ::grpc::Status
    GetDeviceCryptoDirectory(::grpc::ServerContext* context,
                             const ::securecloud::auth::v1::GetDeviceCryptoDirectoryRequest* request,
                             ::securecloud::auth::v1::GetDeviceCryptoDirectoryResponse* response) override;

    ::grpc::Status GetCryptoIdentity(::grpc::ServerContext* context,
                                     const ::securecloud::auth::v1::GetCryptoIdentityRequest* request,
                                     ::securecloud::auth::v1::GetCryptoIdentityResponse* response) override;

    ::grpc::Status UpdateCryptoPrekeys(::grpc::ServerContext* context,
                                       const ::securecloud::auth::v1::UpdateCryptoPrekeysRequest* request,
                                       ::securecloud::auth::v1::UpdateCryptoPrekeysResponse* response) override;

  private:
    [[nodiscard]] std::string extract_client_identity(const ::grpc::ServerContext* context) const;

    void log_rpc_execution(std::string_view rpc_name, const ::grpc::ServerContext* context,
                           const ::grpc::Status& status, std::chrono::microseconds duration) const;

    // Sub-component instances
    std::unique_ptr<AuthenticationController> auth_controller_;
    std::unique_ptr<SessionManager> session_manager_;
    std::unique_ptr<DeviceManager> device_manager_;
    std::unique_ptr<CryptoDirectoryManager> crypto_directory_manager_;
};

} // namespace securecloud::auth::service