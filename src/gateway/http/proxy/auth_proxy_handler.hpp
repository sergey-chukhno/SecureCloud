#pragma once

#include "grpc/auth_client_interface.hpp"
#include "http/auth/authenticated_context.hpp"
#include "http/resilience/bulkhead_manager.hpp"
#include "http/resilience/deadline_manager.hpp"
#include "http/resilience/retry_policy.hpp"

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

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
                              std::shared_ptr<RetryPolicy> retry_policy = nullptr,
                              std::shared_ptr<BulkheadManager> bulkhead_manager = nullptr);
    ~AuthProxyHandler() = default;

    AuthProxyHandler(const AuthProxyHandler&) = delete;
    AuthProxyHandler& operator=(const AuthProxyHandler&) = delete;
    AuthProxyHandler(AuthProxyHandler&&) = delete;
    AuthProxyHandler& operator=(AuthProxyHandler&&) = delete;

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

    [[nodiscard]] const std::shared_ptr<RetryPolicy>& retry_policy() const noexcept { return retry_policy_; }

    [[nodiscard]] const std::shared_ptr<BulkheadManager>& bulkhead_manager() const noexcept {
        return bulkhead_manager_;
    }

    /// Cancels an in-flight request by correlation request_id, triggering TryCancel() on downstream gRPC.
    /// Returns true if an active call context was found and cancelled.
    bool cancel_request(const std::string& request_id);

    void register_active_call(const std::string& request_id, grpc::ClientCallContext* ctx);
    void unregister_active_call(const std::string& request_id);

  private:
    [[nodiscard]] static std::string extract_request_id(const httplib::Request& req);

    std::shared_ptr<grpc::IAuthClient> auth_client_;
    std::shared_ptr<DeadlineManager> deadline_manager_;
    std::shared_ptr<RetryPolicy> retry_policy_;
    std::shared_ptr<BulkheadManager> bulkhead_manager_;

    mutable std::mutex active_calls_mutex_;
    std::unordered_map<std::string, grpc::ClientCallContext*> active_calls_;
};

} // namespace securecloud::gateway::http
