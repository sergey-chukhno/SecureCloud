#pragma once

#include "http/middleware.hpp"

#include <functional>
#include <string>

namespace securecloud::gateway::http {

/// Middleware that logs incoming HTTP requests with latency metrics and secret scrubbing.
class LoggingMiddleware : public Middleware {
  public:
    using LogSink = std::function<void(const std::string&)>;

    explicit LoggingMiddleware(LogSink sink = nullptr);

    void process(const httplib::Request& req, httplib::Response& res, const NextHandler& next) override;

    [[nodiscard]] static bool is_sensitive_auth_route(const std::string& path) noexcept;

  private:
    LogSink sink_;
};

} // namespace securecloud::gateway::http
