#pragma once

#include "gateway_config.hpp"
#include "grpc/client_call_context.hpp"
#include "grpc/dependency_error.hpp"
#include "grpc/messaging_client_interface.hpp"
#include "http/auth/authenticated_context.hpp"
#include "http/resilience/bulkhead_manager.hpp"
#include "http/resilience/circuit_breaker.hpp"
#include "http/resilience/deadline_manager.hpp"
#include "http/resilience/retry_policy.hpp"

#include <chrono>
#include <memory>
#include <string>

namespace httplib {
struct Request;
struct Response;
} // namespace httplib

namespace securecloud::gateway::http {

class Router;

/**
 * @brief HTTP proxy handler forwarding REST conversation and messaging requests to the Messaging Microservice via gRPC.
 *
 * Invariant: Never performs database access directly on Gateway (ADR-005).
 */
class MessagingProxyHandler {
  public:
    explicit MessagingProxyHandler(std::shared_ptr<grpc::IMessagingClient> messaging_client,
                                   std::shared_ptr<DeadlineManager> deadline_manager = nullptr,
                                   std::shared_ptr<RetryPolicy> retry_policy = nullptr,
                                   std::shared_ptr<BulkheadManager> bulkhead_manager = nullptr,
                                   std::shared_ptr<CircuitBreaker> circuit_breaker = nullptr);
    ~MessagingProxyHandler() = default;

    MessagingProxyHandler(const MessagingProxyHandler&) = delete;
    MessagingProxyHandler& operator=(const MessagingProxyHandler&) = delete;
    MessagingProxyHandler(MessagingProxyHandler&&) = delete;
    MessagingProxyHandler& operator=(MessagingProxyHandler&&) = delete;

    /// Registers Messaging service HTTP routes into the provided Router
    void register_routes(Router& router);

    // Route handlers
    void handle_create_conversation(const httplib::Request& req, httplib::Response& res,
                                    const AuthenticatedContext& ctx);
    void handle_get_conversation(const httplib::Request& req, httplib::Response& res, const AuthenticatedContext& ctx);
    void handle_list_conversations(const httplib::Request& req, httplib::Response& res,
                                   const AuthenticatedContext& ctx);
    void handle_add_participant(const httplib::Request& req, httplib::Response& res, const AuthenticatedContext& ctx);
    void handle_remove_participant(const httplib::Request& req, httplib::Response& res,
                                   const AuthenticatedContext& ctx);
    void handle_leave_conversation(const httplib::Request& req, httplib::Response& res,
                                   const AuthenticatedContext& ctx);
    void handle_update_metadata(const httplib::Request& req, httplib::Response& res, const AuthenticatedContext& ctx);
    void handle_send_message(const httplib::Request& req, httplib::Response& res, const AuthenticatedContext& ctx);
    void handle_acknowledge_delivery(const httplib::Request& req, httplib::Response& res,
                                     const AuthenticatedContext& ctx);
    void handle_send_read_receipt(const httplib::Request& req, httplib::Response& res, const AuthenticatedContext& ctx);
    void handle_get_delivery_status(const httplib::Request& req, httplib::Response& res,
                                    const AuthenticatedContext& ctx);
    void handle_sync_messages(const httplib::Request& req, httplib::Response& res, const AuthenticatedContext& ctx);
    void handle_get_sync_cursor(const httplib::Request& req, httplib::Response& res, const AuthenticatedContext& ctx);
    void handle_update_sync_cursor(const httplib::Request& req, httplib::Response& res,
                                   const AuthenticatedContext& ctx);

  private:
    std::shared_ptr<grpc::IMessagingClient> messaging_client_;
    std::shared_ptr<DeadlineManager> deadline_manager_;
    std::shared_ptr<RetryPolicy> retry_policy_;
    std::shared_ptr<BulkheadManager> bulkhead_manager_;
    std::shared_ptr<CircuitBreaker> circuit_breaker_;

    [[nodiscard]] static std::string extract_request_id(const httplib::Request& req);
    [[nodiscard]] std::chrono::milliseconds compute_timeout(const httplib::Request& req) const;
    void write_grpc_error(httplib::Response& res, const grpc::DependencyError& error,
                          const std::string& request_id) const;
};

} // namespace securecloud::gateway::http
