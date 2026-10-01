#pragma once

#include "http/middleware/middleware.hpp"
#include "http/resilience/drain_manager.hpp"

#include <memory>

namespace httplib {
struct Request;
struct Response;
} // namespace httplib

namespace securecloud::gateway::http {

/// Coordinated graceful drain middleware (ADR-009, GW-009-T04).
/// Intercepts inbound HTTP requests before business routing.
/// When the Gateway enters the draining state, new requests are rejected with
/// HTTP 503 SERVER_SHUTTING_DOWN while in-flight requests are permitted to complete cleanly.
class DrainMiddleware : public Middleware {
  public:
    explicit DrainMiddleware(std::shared_ptr<DrainManager> drain_manager);
    ~DrainMiddleware() override = default;

    DrainMiddleware(const DrainMiddleware&) = delete;
    DrainMiddleware& operator=(const DrainMiddleware&) = delete;
    DrainMiddleware(DrainMiddleware&&) noexcept = default;
    DrainMiddleware& operator=(DrainMiddleware&&) noexcept = default;

    void process(const httplib::Request& req, httplib::Response& res, const NextHandler& next) override;

    [[nodiscard]] const std::shared_ptr<DrainManager>& drain_manager() const noexcept { return drain_manager_; }

  private:
    std::shared_ptr<DrainManager> drain_manager_;
};

} // namespace securecloud::gateway::http
