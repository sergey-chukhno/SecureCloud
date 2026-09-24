#pragma once

#include "gateway_config.hpp"
#include "http/middleware.hpp"

#include <atomic>
#include <cstddef>
#include <memory>
#include <string>

namespace httplib {
struct Request;
struct Response;
} // namespace httplib

namespace securecloud::gateway::http {

/// Transport-level and pre-routing resource constraints middleware (GW-002-TC-04).
/// Enforces bounded request headers (HTTP 431), bounded body size (HTTP 413),
/// and maximum concurrent in-flight requests (HTTP 503) using RFC 7807 problem details.
class ResourceLimiterMiddleware : public Middleware {
  public:
    static constexpr const char* k_content_type_problem_json = "application/problem+json";
    static constexpr const char* k_header_retry_after = "Retry-After";
    static constexpr const char* k_default_retry_after_seconds = "5";

    explicit ResourceLimiterMiddleware(GatewayResourceLimitsConfig limits);
    explicit ResourceLimiterMiddleware(const GatewayConfig& config);
    ~ResourceLimiterMiddleware() override = default;

    ResourceLimiterMiddleware(const ResourceLimiterMiddleware&) = delete;
    ResourceLimiterMiddleware& operator=(const ResourceLimiterMiddleware&) = delete;
    ResourceLimiterMiddleware(ResourceLimiterMiddleware&& other) noexcept;
    ResourceLimiterMiddleware& operator=(ResourceLimiterMiddleware&& other) noexcept;

    void process(const httplib::Request& req, httplib::Response& res, const NextHandler& next) override;

    [[nodiscard]] size_t active_connections() const noexcept;
    [[nodiscard]] const GatewayResourceLimitsConfig& limits() const noexcept;

  private:
    [[nodiscard]] static size_t calculate_total_header_bytes(const httplib::Request& req) noexcept;
    [[nodiscard]] static std::string extract_request_id(const httplib::Request& req, const httplib::Response& res);

    static void write_problem_details(httplib::Response& res, int status, const std::string& type,
                                      const std::string& title, const std::string& detail,
                                      const std::string& request_id);

    GatewayResourceLimitsConfig limits_;
    mutable std::atomic<size_t> active_connections_{0};
};

} // namespace securecloud::gateway::http
