#include "http/logging_middleware.hpp"

#include "http/request_id_middleware.hpp"

#include <chrono>
#include <httplib.h>
#include <iostream>
#include <string>
#include <utility>

namespace securecloud::gateway::http {

LoggingMiddleware::LoggingMiddleware(LogSink sink) : sink_(std::move(sink)) {}

bool LoggingMiddleware::is_sensitive_auth_route(const std::string& path) noexcept {
    return path.starts_with("/auth") || path.starts_with("/api/v1/auth");
}

void LoggingMiddleware::process(const httplib::Request& req, httplib::Response& res, const NextHandler& next) {
    auto start_time = std::chrono::steady_clock::now();

    next(req, res);

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time);

    std::string req_id;
    if (res.has_header(RequestIdMiddleware::k_request_id_header)) {
        req_id = res.get_header_value(RequestIdMiddleware::k_request_id_header);
    }

    std::string line = "[HTTP] " + req.method + " " + req.path + " -> " + std::to_string(res.status) + " (" +
                       std::to_string(elapsed.count()) + "ms)";
    if (!req_id.empty()) {
        line += " [" + req_id + "]";
    }

    if (sink_) {
        sink_(line);
    } else {
        std::cout << line << "\n";
    }
}

} // namespace securecloud::gateway::http
