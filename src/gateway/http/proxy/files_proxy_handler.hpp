#pragma once

#include "gateway_config.hpp"
#include "grpc/client_call_context.hpp"
#include "grpc/dependency_error.hpp"
#include "grpc/files_client_interface.hpp"
#include "http/auth/authenticated_context.hpp"
#include "http/resilience/bulkhead_manager.hpp"
#include "http/resilience/circuit_breaker.hpp"
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
 * @brief HTTP proxy handler forwarding REST/HTTP streaming requests to the Files Microservice via gRPC.
 *
 * FilesProxyHandler acts as the protocol boundary between external HTTP streaming clients and the internal
 * gRPC FilesService. It enforces request payload validation, invokes typed RPCs over the mTLS channel,
 * enforces bulkhead limits and circuit breaking, and translates gRPC status codes to RFC 7807 problem details.
 *
 * Invariant: Never performs database access or object storage access directly on Gateway (ADR-005).
 */
class FilesProxyHandler {
  public:
    explicit FilesProxyHandler(std::shared_ptr<grpc::IFilesClient> files_client,
                               std::shared_ptr<DeadlineManager> deadline_manager = nullptr,
                               std::shared_ptr<RetryPolicy> retry_policy = nullptr,
                               std::shared_ptr<BulkheadManager> bulkhead_manager = nullptr,
                               std::shared_ptr<CircuitBreaker> circuit_breaker = nullptr,
                               GatewayStreamingConfig streaming_config = {});
    ~FilesProxyHandler() = default;

    FilesProxyHandler(const FilesProxyHandler&) = delete;
    FilesProxyHandler& operator=(const FilesProxyHandler&) = delete;
    FilesProxyHandler(FilesProxyHandler&&) = delete;
    FilesProxyHandler& operator=(FilesProxyHandler&&) = delete;

    /// Registers Files service HTTP routes into the provided Router
    void register_routes(Router& router);

    // Route handlers
    void handle_upload_init(const httplib::Request& req, httplib::Response& res, const AuthenticatedContext& ctx);
    void handle_upload_chunk(const httplib::Request& req, httplib::Response& res, const AuthenticatedContext& ctx);
    void handle_upload_finalize(const httplib::Request& req, httplib::Response& res, const AuthenticatedContext& ctx);
    void handle_upload_cancel(const httplib::Request& req, httplib::Response& res, const AuthenticatedContext& ctx);
    void handle_get_metadata(const httplib::Request& req, httplib::Response& res, const AuthenticatedContext& ctx);
    void handle_download_chunk(const httplib::Request& req, httplib::Response& res, const AuthenticatedContext& ctx);
    void handle_streaming_download(const httplib::Request& req, httplib::Response& res,
                                   const AuthenticatedContext& ctx);
    void handle_delete_file(const httplib::Request& req, httplib::Response& res, const AuthenticatedContext& ctx);

    [[nodiscard]] const std::shared_ptr<grpc::IFilesClient>& files_client() const noexcept { return files_client_; }

    [[nodiscard]] const std::shared_ptr<DeadlineManager>& deadline_manager() const noexcept {
        return deadline_manager_;
    }

    [[nodiscard]] const std::shared_ptr<RetryPolicy>& retry_policy() const noexcept { return retry_policy_; }

    [[nodiscard]] const std::shared_ptr<BulkheadManager>& bulkhead_manager() const noexcept {
        return bulkhead_manager_;
    }

    [[nodiscard]] const std::shared_ptr<CircuitBreaker>& circuit_breaker() const noexcept { return circuit_breaker_; }

    [[nodiscard]] const GatewayStreamingConfig& streaming_config() const noexcept { return streaming_config_; }

    /// Cancels an in-flight request by correlation request_id, triggering TryCancel() on downstream gRPC.
    /// Returns true if an active call context was found and cancelled.
    bool cancel_request(const std::string& request_id);

    void register_active_call(const std::string& request_id, grpc::ClientCallContext* ctx);
    void unregister_active_call(const std::string& request_id);

  private:
    [[nodiscard]] static std::string extract_request_id(const httplib::Request& req);
    [[nodiscard]] static std::string extract_file_id(const httplib::Request& req);
    [[nodiscard]] std::chrono::milliseconds compute_timeout(const httplib::Request& req) const;
    void write_grpc_error(httplib::Response& res, const grpc::DependencyError& error,
                          const std::string& request_id) const;

    std::shared_ptr<grpc::IFilesClient> files_client_;
    std::shared_ptr<DeadlineManager> deadline_manager_;
    std::shared_ptr<RetryPolicy> retry_policy_;
    std::shared_ptr<BulkheadManager> bulkhead_manager_;
    std::shared_ptr<CircuitBreaker> circuit_breaker_;
    GatewayStreamingConfig streaming_config_;

    mutable std::mutex active_calls_mutex_;
    std::unordered_map<std::string, grpc::ClientCallContext*> active_calls_;
};

} // namespace securecloud::gateway::http
