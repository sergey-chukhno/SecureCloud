#pragma once

#include "http/middleware.hpp"

#include <string>

namespace securecloud::gateway::http {

/// Middleware that generates or propagates standard X-Request-Id headers.
class RequestIdMiddleware : public Middleware {
  public:
    static constexpr const char* k_request_id_header = "X-Request-Id";

    [[nodiscard]] static std::string generate_uuid_v4();

    void process(const httplib::Request& req, httplib::Response& res, const NextHandler& next) override;
};

} // namespace securecloud::gateway::http
