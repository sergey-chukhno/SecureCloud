#pragma once

#include "securecloud/auth/v1/auth.grpc.pb.h"
#include "service/audit_event_publisher.hpp"
#include "service/credential_verifier.hpp"
#include "service/mfa_manager.hpp"
#include "service/session_manager.hpp"
#include "service/token_manager.hpp"

#include <chrono>
#include <grpcpp/grpcpp.h>
#include <memory>
#include <string>
#include <string_view>

namespace securecloud::auth::service {

// Forward declarations of modular sub-components for future tickets
class AuthenticationController;
class DeviceManager;
class CryptoDirectoryManager;

/// Implementation of the securecloud.auth.v1.AuthService gRPC interface.
class AuthServiceImpl final : public securecloud::auth::v1::AuthService::Service {
  public:
    explicit AuthServiceImpl(std::shared_ptr<ICredentialVerifier> credential_verifier = nullptr,
                             std::shared_ptr<ISessionManager> session_manager = nullptr,
                             std::shared_ptr<IAuditEventPublisher> audit_publisher = nullptr,
                             std::shared_ptr<ITokenManager> token_manager = nullptr,
                             std::shared_ptr<IMfaManager> mfa_manager = nullptr);
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

    // --- MFA RPC Implementations ---

    ::grpc::Status VerifyMfaChallenge(::grpc::ServerContext* context,
                                      const ::securecloud::auth::v1::VerifyMfaChallengeRequest* request,
                                      ::securecloud::auth::v1::VerifyMfaChallengeResponse* response) override;

    ::grpc::Status InitiateMfaEnrollment(::grpc::ServerContext* context,
                                         const ::securecloud::auth::v1::InitiateMfaEnrollmentRequest* request,
                                         ::securecloud::auth::v1::InitiateMfaEnrollmentResponse* response) override;

    ::grpc::Status ConfirmMfaEnrollment(::grpc::ServerContext* context,
                                        const ::securecloud::auth::v1::ConfirmMfaEnrollmentRequest* request,
                                        ::securecloud::auth::v1::ConfirmMfaEnrollmentResponse* response) override;

    ::grpc::Status DisableMfa(::grpc::ServerContext* context,
                              const ::securecloud::auth::v1::DisableMfaRequest* request,
                              ::securecloud::auth::v1::DisableMfaResponse* response) override;

  private:
    [[nodiscard]] std::string extract_client_identity(const ::grpc::ServerContext* context) const;

    void log_rpc_execution(std::string_view rpc_name, const ::grpc::ServerContext* context,
                           const ::grpc::Status& status, std::chrono::microseconds duration) const;

    // Injected domain services
    std::shared_ptr<ICredentialVerifier> credential_verifier_;
    std::shared_ptr<ISessionManager> session_manager_;
    std::shared_ptr<IAuditEventPublisher> audit_publisher_;
    std::shared_ptr<ITokenManager> token_manager_;
    std::shared_ptr<IMfaManager> mfa_manager_;

    // Sub-component instances
    std::unique_ptr<AuthenticationController> auth_controller_;
    std::unique_ptr<DeviceManager> device_manager_;
    std::unique_ptr<CryptoDirectoryManager> crypto_directory_manager_;
};

} // namespace securecloud::auth::service