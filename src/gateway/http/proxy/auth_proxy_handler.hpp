#pragma once

#include "grpc/auth_client_interface.hpp"
#include "http/auth/authenticated_context.hpp"
#include "http/deadline_manager.hpp"
#include "http/retry_policy.hpp"

#include <memory>
#include <string>

namespace httplib {
struct Request;
struct Response;
} // namespace httplib

namespace securecloud::gateway::http {

class Router;

/**
 * @brief HTTP proxy handler forwarding authentication requests to the Auth Microservice via gRPC.
 *
 * AuthProxyHandler acts as the protocol boundary between external HTTP/JSON clients and the internal
 * gRPC AuthService. It enforces request payload validation, invokes typed RPCs over the mTLS channel,
 * and translates gRPC status codes to RFC 7807 problem details HTTP responses.
 *
 * Invariant: Never performs backend authentication or database access directly (ADR-005).
 */
class AuthProxyHandler {
  public:
    explicit AuthProxyHandler(std::shared_ptr<grpc::IAuthClient> auth_client,
                              std::shared_ptr<DeadlineManager> deadline_manager = nullptr,
                              std::shared_ptr<RetryPolicy> retry_policy = nullptr);
    ~AuthProxyHandler() = default;

    AuthProxyHandler(const AuthProxyHandler&) = delete;
    AuthProxyHandler& operator=(const AuthProxyHandler&) = delete;
    AuthProxyHandler(AuthProxyHandler&&) noexcept = default;
    AuthProxyHandler& operator=(AuthProxyHandler&&) noexcept = default;

    /// Registers the Auth service HTTP routes into the provided Router
    void register_routes(Router& router);

    // Route handlers
    void handle_login(const httplib::Request& req, httplib::Response& res);
    void handle_refresh(const httplib::Request& req, httplib::Response& res);
    void handle_revoke(const httplib::Request& req, httplib::Response& res, const AuthenticatedContext& ctx);
    void handle_get_me(const httplib::Request& req, httplib::Response& res, const AuthenticatedContext& ctx);
    void handle_register_device(const httplib::Request& req, httplib::Response& res, const AuthenticatedContext& ctx);

    [[nodiscard]] const std::shared_ptr<DeadlineManager>& deadline_manager() const noexcept {
        return deadline_manager_;
    }

    [[nodiscard]] const std::shared_ptr<RetryPolicy>& retry_policy() const noexcept {
        return retry_policy_;
    }

  private:
    [[nodiscard]] static std::string extract_request_id(const httplib::Request& req);

    std::shared_ptr<grpc::IAuthClient> auth_client_;
    std::shared_ptr<DeadlineManager> deadline_manager_;
    std::shared_ptr<RetryPolicy> retry_policy_;
};

} // namespace securecloud::gateway::http
