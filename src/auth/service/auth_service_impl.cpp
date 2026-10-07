#include "auth/service/auth_service_impl.hpp"

#include "securecloud/security/mtls_config.hpp"

#include <chrono>
#include <iostream>
#include <string_view>

namespace securecloud::auth::service {

// Temporary stub class definitions to satisfy std::unique_ptr<T> requirements
// until full controller/manager implementations are added in future tickets.
class AuthenticationController {};
class DeviceManager {};
class CryptoDirectoryManager {};

AuthServiceImpl::AuthServiceImpl(std::shared_ptr<ICredentialVerifier> credential_verifier,
                                 std::shared_ptr<ISessionManager> session_manager,
                                 std::shared_ptr<IAuditEventPublisher> audit_publisher,
                                 std::shared_ptr<ITokenManager> token_manager)
    : credential_verifier_(std::move(credential_verifier)), session_manager_(std::move(session_manager)),
      audit_publisher_(std::move(audit_publisher)), token_manager_(std::move(token_manager)) {}

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

::grpc::Status AuthServiceImpl::Authenticate(::grpc::ServerContext* context,
                                             const ::securecloud::auth::v1::AuthenticateRequest* request,
                                             ::securecloud::auth::v1::AuthenticateResponse* response) {
    auto start = std::chrono::steady_clock::now();

    if (!request || !response) {
        auto status = ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Request and response must not be null");
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
        log_rpc_execution("Authenticate", context, status, duration);
        return status;
    }

    if (!credential_verifier_ || !session_manager_) {
        auto status = ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "Authenticate RPC dependencies not configured");
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
        log_rpc_execution("Authenticate", context, status, duration);
        return status;
    }

    std::string client_ip = context ? context->peer() : "unknown";

    // 1. Syntactic / Schema validation of inputs
    auto id_res = domain::CredentialIdentifier::create(request->credential_identifier());
    if (!id_res.has_value()) {
        if (audit_publisher_) {
            audit_publisher_->publish(domain::AuditEvent::login_failed(request->credential_identifier(),
                                                                       "Invalid credential identifier format",
                                                                       std::nullopt, std::nullopt, client_ip));
        }
        auto status = ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Invalid credential identifier format");
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
        log_rpc_execution("Authenticate", context, status, duration);
        return status;
    }

    auto pass_res = domain::PasswordCredential::create(request->password());
    if (!pass_res.has_value()) {
        if (audit_publisher_) {
            audit_publisher_->publish(domain::AuditEvent::login_failed(
                id_res->value(), "Invalid password format or length", std::nullopt, std::nullopt, client_ip));
        }
        auto status = ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Invalid password format or length");
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
        log_rpc_execution("Authenticate", context, status, duration);
        return status;
    }

    auto dev_id_res = domain::Uuid::from_string(request->device_id());
    if (!dev_id_res.has_value()) {
        if (audit_publisher_) {
            audit_publisher_->publish(domain::AuditEvent::login_failed(id_res->value(), "Invalid device UUID format",
                                                                       std::nullopt, std::nullopt, client_ip));
        }
        auto status = ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Invalid device UUID format");
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
        log_rpc_execution("Authenticate", context, status, duration);
        return status;
    }

    // 2. Primary Credential Verification
    auto auth_result = credential_verifier_->verify(*id_res, *pass_res);
    if (auth_result.status == domain::AuthenticationStatus::InvalidCredentials) {
        if (audit_publisher_) {
            audit_publisher_->publish(domain::AuditEvent::login_failed(id_res->value(), "Invalid credentials",
                                                                       std::nullopt, *dev_id_res, client_ip));
        }
        auto status = ::grpc::Status(::grpc::StatusCode::UNAUTHENTICATED, "Invalid credentials");
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
        log_rpc_execution("Authenticate", context, status, duration);
        return status;
    }

    if (auth_result.status == domain::AuthenticationStatus::AccountDisabled) {
        std::optional<domain::Uuid> uid =
            auth_result.user.has_value() ? std::make_optional(auth_result.user->user_id) : std::nullopt;
        if (audit_publisher_) {
            audit_publisher_->publish(domain::AuditEvent::account_disabled_attempt(
                uid, id_res->value(), "Account is disabled", *dev_id_res, client_ip));
        }
        auto status = ::grpc::Status(::grpc::StatusCode::PERMISSION_DENIED, "Account is disabled");
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
        log_rpc_execution("Authenticate", context, status, duration);
        return status;
    }

    if (!auth_result.is_success() || !auth_result.user.has_value()) {
        auto status = ::grpc::Status(::grpc::StatusCode::INTERNAL, "Authentication service internal error");
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
        log_rpc_execution("Authenticate", context, status, duration);
        return status;
    }

    // 3. Session Establishment
    const auto& user = auth_result.user.value();
    auto session_result = session_manager_->establish_session(user, *dev_id_res);
    if (session_result.status == SessionEstablishmentStatus::DeviceNotFound) {
        if (audit_publisher_) {
            audit_publisher_->publish(domain::AuditEvent::login_failed(
                id_res->value(), "Device not found or not registered to user", user.user_id, *dev_id_res, client_ip));
        }
        auto status = ::grpc::Status(::grpc::StatusCode::NOT_FOUND, "Device not found or not registered to user");
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
        log_rpc_execution("Authenticate", context, status, duration);
        return status;
    }

    if (session_result.status == SessionEstablishmentStatus::DeviceRevoked) {
        if (audit_publisher_) {
            audit_publisher_->publish(domain::AuditEvent::login_failed(id_res->value(), "Device is revoked",
                                                                       user.user_id, *dev_id_res, client_ip));
        }
        auto status = ::grpc::Status(::grpc::StatusCode::PERMISSION_DENIED, "Device is revoked");
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
        log_rpc_execution("Authenticate", context, status, duration);
        return status;
    }

    if (!session_result.is_success() || !session_result.session.has_value()) {
        auto status = ::grpc::Status(::grpc::StatusCode::INTERNAL, "Session establishment internal error");
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
        log_rpc_execution("Authenticate", context, status, duration);
        return status;
    }

    // 4. Success Response and Audit Emission
    const auto& session = session_result.session.value();
    if (audit_publisher_) {
        audit_publisher_->publish(domain::AuditEvent::login_succeeded(user.user_id, id_res->value(), *dev_id_res,
                                                                      session.session_id, client_ip));
    }

    response->set_session_id(session.session_id.to_string());
    response->set_user_id(user.user_id.to_string());
    response->set_authentication_level(securecloud::auth::v1::AUTHENTICATION_LEVEL_PRIMARY);
    auto expires_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(session.expires_at.time_since_epoch()).count();

    if (token_manager_) {
        auto tokens = token_manager_->issue_initial_tokens(session);
        response->set_access_token(tokens.access_token);
        response->set_refresh_token(tokens.refresh_token.raw_secret());
        expires_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(tokens.expires_at.time_since_epoch()).count();
    }

    response->set_expires_at_epoch_ms(expires_ms);
    response->set_mfa_required(false);

    auto status = ::grpc::Status::OK;
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
    log_rpc_execution("Authenticate", context, status, duration);
    return status;
}

::grpc::Status AuthServiceImpl::ValidateSession(::grpc::ServerContext* context,
                                                const ::securecloud::auth::v1::ValidateSessionRequest* request,
                                                ::securecloud::auth::v1::ValidateSessionResponse* response) {
    auto start = std::chrono::steady_clock::now();

    if (!request || !response) {
        auto status = ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Null request or response");
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
        log_rpc_execution("ValidateSession", context, status, duration);
        return status;
    }

    if (!session_manager_) {
        auto status = ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "SessionManager dependency is unconfigured");
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
        log_rpc_execution("ValidateSession", context, status, duration);
        return status;
    }

    auto session_id_res = domain::Uuid::from_string(request->session_id());
    if (!session_id_res.has_value()) {
        auto status = ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Invalid session_id UUID format");
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
        log_rpc_execution("ValidateSession", context, status, duration);
        return status;
    }

    auto result = session_manager_->validate_session(*session_id_res);
    if (result.is_valid() && result.session.has_value()) {
        const auto& session = *result.session;
        response->set_is_valid(true);
        response->set_user_id(session.user_id.to_string());
        response->set_device_id(session.device_id.to_string());
        response->set_authentication_level(session.authentication_level == domain::AuthenticationLevel::MfaVerified
                                               ? securecloud::auth::v1::AUTHENTICATION_LEVEL_MFA_VERIFIED
                                               : securecloud::auth::v1::AUTHENTICATION_LEVEL_PRIMARY);
        auto expires_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(session.expires_at.time_since_epoch()).count();
        response->set_expires_at_epoch_ms(expires_ms);
    } else {
        response->set_is_valid(false);
    }

    auto status = ::grpc::Status::OK;
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
    log_rpc_execution("ValidateSession", context, status, duration);
    return status;
}

::grpc::Status AuthServiceImpl::RevokeSession(::grpc::ServerContext* context,
                                              const ::securecloud::auth::v1::RevokeSessionRequest* request,
                                              ::securecloud::auth::v1::RevokeSessionResponse* response) {
    auto start = std::chrono::steady_clock::now();

    if (!request || !response) {
        auto status = ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Null request or response");
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
        log_rpc_execution("RevokeSession", context, status, duration);
        return status;
    }

    if (!session_manager_) {
        auto status = ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "SessionManager dependency is unconfigured");
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
        log_rpc_execution("RevokeSession", context, status, duration);
        return status;
    }

    auto session_id_res = domain::Uuid::from_string(request->session_id());
    if (!session_id_res.has_value()) {
        auto status = ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Invalid session_id UUID format");
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
        log_rpc_execution("RevokeSession", context, status, duration);
        return status;
    }

    auto result = session_manager_->revoke_session(*session_id_res, request->reason());
    response->set_revoked(result.is_success());

    auto status = ::grpc::Status::OK;
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
    log_rpc_execution("RevokeSession", context, status, duration);
    return status;
}

::grpc::Status AuthServiceImpl::RefreshSession(::grpc::ServerContext* context,
                                               const ::securecloud::auth::v1::RefreshSessionRequest* request,
                                               ::securecloud::auth::v1::RefreshSessionResponse* response) {
    auto start = std::chrono::steady_clock::now();

    if (!request || !response) {
        auto status = ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Null request or response");
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
        log_rpc_execution("RefreshSession", context, status, duration);
        return status;
    }

    if (!token_manager_) {
        auto status = ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "TokenManager dependency is unconfigured");
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
        log_rpc_execution("RefreshSession", context, status, duration);
        return status;
    }

    if (request->refresh_token().empty()) {
        auto status = ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Refresh token must not be empty");
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
        log_rpc_execution("RefreshSession", context, status, duration);
        return status;
    }

    auto dev_id_res = domain::Uuid::from_string(request->device_id());
    if (!dev_id_res.has_value()) {
        auto status = ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Invalid device UUID format");
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
        log_rpc_execution("RefreshSession", context, status, duration);
        return status;
    }

    std::string client_ip = extract_client_identity(context);
    auto refresh_result = token_manager_->refresh_tokens(request->refresh_token(), *dev_id_res, client_ip);

    ::grpc::Status status = ::grpc::Status::OK;
    switch (refresh_result.status) {
    case domain::TokenRefreshStatus::Success: {
        if (refresh_result.tokens.has_value() && refresh_result.session_id.has_value()) {
            const auto& tokens = refresh_result.tokens.value();
            response->set_session_id(refresh_result.session_id->to_string());
            response->set_access_token(tokens.access_token);
            response->set_new_refresh_token(tokens.refresh_token.raw_secret());
            int64_t expires_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(tokens.expires_at.time_since_epoch()).count();
            response->set_expires_at_epoch_ms(expires_ms);
            status = ::grpc::Status::OK;
        } else {
            status = ::grpc::Status(::grpc::StatusCode::INTERNAL, "Inconsistent token refresh result state");
        }
        break;
    }
    case domain::TokenRefreshStatus::InvalidToken:
    case domain::TokenRefreshStatus::ExpiredToken:
    case domain::TokenRefreshStatus::SessionRevoked: {
        status = ::grpc::Status(::grpc::StatusCode::UNAUTHENTICATED, refresh_result.error_message.empty()
                                                                         ? "Invalid or expired refresh token"
                                                                         : refresh_result.error_message);
        break;
    }
    case domain::TokenRefreshStatus::CompromiseDetected: {
        status = ::grpc::Status(::grpc::StatusCode::UNAUTHENTICATED, "Refresh token reuse detected; session revoked");
        break;
    }
    case domain::TokenRefreshStatus::DeviceMismatch: {
        status = ::grpc::Status(::grpc::StatusCode::PERMISSION_DENIED, refresh_result.error_message.empty()
                                                                           ? "Device mismatch for refresh token"
                                                                           : refresh_result.error_message);
        break;
    }
    case domain::TokenRefreshStatus::ConcurrencyConflict: {
        status =
            ::grpc::Status(::grpc::StatusCode::ABORTED, "Concurrent refresh detected; please retry with current token");
        break;
    }
    case domain::TokenRefreshStatus::DatabaseError:
    default: {
        status = ::grpc::Status(::grpc::StatusCode::INTERNAL, refresh_result.error_message.empty()
                                                                  ? "Internal token refresh error"
                                                                  : refresh_result.error_message);
        break;
    }
    }

    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
    log_rpc_execution("RefreshSession", context, status, duration);
    return status;
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

// 8 Remaining Unimplemented Proto RPCs
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