#pragma once

#include "http/proxy/auth_proxy_handler.hpp"
#include "http/routing/router.hpp"

#include <memory>

namespace securecloud::common::health {
class HealthStatusManager;
}

namespace securecloud::gateway::http {

/**
 * @brief Centralized route registrar assembling perimeter routes into the HTTP Router.
 *
 * Configures the complete route mapping for the Gateway:
 * - Health check endpoints (/health/live, /health/ready)
 * - Auth Microservice proxy endpoints and aliases via AuthProxyHandler
 * - Stubbed endpoints for downstream microservices awaiting Phase 2 implementation
 *
 * Invariant: Never performs backend authentication or database access directly (ADR-005).
 */
class BulkheadManager;

class GatewayRouteRegistrar {
  public:
    GatewayRouteRegistrar(std::shared_ptr<AuthProxyHandler> auth_proxy,
                          common::health::HealthStatusManager& health_manager,
                          std::shared_ptr<BulkheadManager> bulkhead_manager = nullptr);

    GatewayRouteRegistrar(std::shared_ptr<AuthProxyHandler> auth_proxy,
                          std::shared_ptr<common::health::HealthStatusManager> health_manager,
                          std::shared_ptr<BulkheadManager> bulkhead_manager = nullptr);

    ~GatewayRouteRegistrar() = default;

    GatewayRouteRegistrar(const GatewayRouteRegistrar&) = delete;
    GatewayRouteRegistrar& operator=(const GatewayRouteRegistrar&) = delete;
    GatewayRouteRegistrar(GatewayRouteRegistrar&&) noexcept = default;
    GatewayRouteRegistrar& operator=(GatewayRouteRegistrar&&) noexcept = default;

    /// Registers all perimeter routes into the given router
    void register_all_routes(Router& router);

    /// Registers liveness and readiness probe routes
    void register_health_routes(Router& router);

    /// Registers Auth microservice proxy routes and aliases
    void register_auth_routes(Router& router);

    /// Registers placeholder stub routes for downstream microservices
    void register_stub_routes(Router& router);

  private:
    std::shared_ptr<AuthProxyHandler> auth_proxy_;
    std::shared_ptr<common::health::HealthStatusManager> health_manager_ptr_;
    common::health::HealthStatusManager* health_manager_{nullptr};
    std::shared_ptr<BulkheadManager> bulkhead_manager_;
};

} // namespace securecloud::gateway::http
