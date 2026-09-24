#include "http/resource_limiter_middleware.hpp"

#include "http/request_id_middleware.hpp"

#include <charconv>
#include <exception>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <string>
#include <utility>

namespace securecloud::gateway::http {

namespace {

constexpr int k_status_payload_too_large = 413;
constexpr int k_status_header_fields_too_large = 431;
constexpr int k_status_service_unavailable = 503;

constexpr const char* k_type_header_too_large = "urn:securecloud:error:header_too_large";
constexpr const char* k_title_header_too_large = "Request Header Fields Too Large";

constexpr const char* k_type_payload_too_large = "urn:securecloud:error:payload_too_large";
constexpr const char* k_title_payload_too_large = "Payload Too Large";

constexpr const char* k_type_service_unavailable = "urn:securecloud:error:service_unavailable";
constexpr const char* k_title_service_unavailable = "Service Unavailable";

constexpr const char* k_header_content_length = "Content-Length";

struct ConnectionScopeGuard {
    std::atomic<size_t>& counter;
    ~ConnectionScopeGuard() noexcept { counter.fetch_sub(1, std::memory_order_relaxed); }
};

} // namespace

ResourceLimiterMiddleware::ResourceLimiterMiddleware(GatewayResourceLimitsConfig limits) : limits_(limits) {}

ResourceLimiterMiddleware::ResourceLimiterMiddleware(const GatewayConfig& config) : limits_(config.limits) {}

ResourceLimiterMiddleware::ResourceLimiterMiddleware(ResourceLimiterMiddleware&& other) noexcept
    : limits_(other.limits_), active_connections_(other.active_connections_.load()) {}

ResourceLimiterMiddleware& ResourceLimiterMiddleware::operator=(ResourceLimiterMiddleware&& other) noexcept {
    if (this != &other) {
        limits_ = other.limits_;
        active_connections_.store(other.active_connections_.load());
    }
    return *this;
}

size_t ResourceLimiterMiddleware::calculate_total_header_bytes(const httplib::Request& req) noexcept {
    size_t total = 0;
    for (const auto& [key, value] : req.headers) {
        total += key.size() + value.size();
    }
    return total;
}

std::string ResourceLimiterMiddleware::extract_request_id(const httplib::Request& req, const httplib::Response& res) {
    if (res.has_header(RequestIdMiddleware::k_request_id_header)) {
        return res.get_header_value(RequestIdMiddleware::k_request_id_header);
    }
    if (req.has_header(RequestIdMiddleware::k_request_id_header)) {
        return req.get_header_value(RequestIdMiddleware::k_request_id_header);
    }
    return "";
}

void ResourceLimiterMiddleware::write_problem_details(httplib::Response& res, int status, const std::string& type,
                                                      const std::string& title, const std::string& detail,
                                                      const std::string& request_id) {
    nlohmann::json problem;
    problem["type"] = type;
    problem["title"] = title;
    problem["status"] = status;
    problem["detail"] = detail;
    if (!request_id.empty()) {
        problem["request_id"] = request_id;
    }

    res.status = status;
    res.set_content(problem.dump(), k_content_type_problem_json);
}

void ResourceLimiterMiddleware::process(const httplib::Request& req, httplib::Response& res, const NextHandler& next) {
    std::string req_id = extract_request_id(req, res);

    // 1. Header size boundary check (HTTP 431)
    size_t header_bytes = calculate_total_header_bytes(req);
    if (header_bytes > limits_.max_header_bytes) {
        write_problem_details(res, k_status_header_fields_too_large, k_type_header_too_large, k_title_header_too_large,
                              "Request headers total size (" + std::to_string(header_bytes) +
                                  " bytes) exceeds maximum limit of " + std::to_string(limits_.max_header_bytes) +
                                  " bytes",
                              req_id);
        return;
    }

    // 2. Early Content-Length fast-path boundary check (HTTP 413)
    if (req.has_header(k_header_content_length)) {
        auto cl_str = req.get_header_value(k_header_content_length);
        size_t content_length = 0;
        auto [ptr, ec] = std::from_chars(cl_str.data(), cl_str.data() + cl_str.size(), content_length);
        if (ec == std::errc{} && content_length > limits_.max_body_bytes) {
            write_problem_details(res, k_status_payload_too_large, k_type_payload_too_large, k_title_payload_too_large,
                                  "Content-Length (" + std::to_string(content_length) +
                                      " bytes) exceeds maximum limit of " + std::to_string(limits_.max_body_bytes) +
                                      " bytes",
                                  req_id);
            return;
        }
    }

    // 3. Body size boundary check (HTTP 413)
    if (req.body.size() > limits_.max_body_bytes) {
        write_problem_details(res, k_status_payload_too_large, k_type_payload_too_large, k_title_payload_too_large,
                              "Request body size (" + std::to_string(req.body.size()) +
                                  " bytes) exceeds maximum limit of " + std::to_string(limits_.max_body_bytes) +
                                  " bytes",
                              req_id);
        return;
    }

    // 4. Concurrent in-flight request boundary check (HTTP 503)
    size_t current = active_connections_.fetch_add(1, std::memory_order_relaxed);
    if (current >= limits_.max_concurrent_connections) {
        active_connections_.fetch_sub(1, std::memory_order_relaxed);
        res.set_header(k_header_retry_after, k_default_retry_after_seconds);
        write_problem_details(res, k_status_service_unavailable, k_type_service_unavailable,
                              k_title_service_unavailable,
                              "Active in-flight requests reached concurrency capacity limit of " +
                                  std::to_string(limits_.max_concurrent_connections),
                              req_id);
        return;
    }

    // RAII guard to decrement active requests counter upon completion or exception
    ConnectionScopeGuard guard{active_connections_};
    next(req, res);
}

size_t ResourceLimiterMiddleware::active_connections() const noexcept {
    return active_connections_.load(std::memory_order_relaxed);
}

const GatewayResourceLimitsConfig& ResourceLimiterMiddleware::limits() const noexcept {
    return limits_;
}

} // namespace securecloud::gateway::http
