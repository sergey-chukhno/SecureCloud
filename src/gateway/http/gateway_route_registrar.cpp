#include "http/gateway_route_registrar.hpp"

#include "http/auth/request_context.hpp"
#include "http/error_mapper.hpp"
#include "securecloud/health/health_status_manager.hpp"

#include <httplib.h>
#include <stdexcept>
#include <string>
#include <utility>

namespace securecloud::gateway::http {
namespace {

constexpr int k_http_status_ok = 200;
constexpr int k_http_status_service_unavailable = 503;

} // namespace

GatewayRouteRegistrar::GatewayRouteRegistrar(std::shared_ptr<AuthProxyHandler> auth_proxy,
                                             common::health::HealthStatusManager& health_manager)
    : auth_proxy_(std::move(auth_proxy)), health_manager_(&health_manager) {
    if (!auth_proxy_) {
        throw std::invalid_argument("GatewayRouteRegistrar: auth_proxy must not be null");
    }
}

GatewayRouteRegistrar::GatewayRouteRegistrar(std::shared_ptr<AuthProxyHandler> auth_proxy,
                                             std::shared_ptr<common::health::HealthStatusManager> health_manager)
    : auth_proxy_(std::move(auth_proxy)), health_manager_ptr_(std::move(health_manager)),
      health_manager_(health_manager_ptr_.get()) {
    if (!auth_proxy_) {
        throw std::invalid_argument("GatewayRouteRegistrar: auth_proxy must not be null");
    }
    if (!health_manager_) {
        throw std::invalid_argument("GatewayRouteRegistrar: health_manager must not be null");
    }
}

void GatewayRouteRegistrar::register_all_routes(Router& router) {
    register_health_routes(router);
    register_auth_routes(router);
    register_stub_routes(router);
}

void GatewayRouteRegistrar::register_health_routes(Router& router) {
    auto* hm = health_manager_;
    router.get("/health/live", [hm](const httplib::Request&, httplib::Response& res) {
        if (hm && hm->is_live()) {
            res.status = k_http_status_ok;
            res.set_content(R"({"status":"SERVING"})", "application/json");
        } else {
            res.status = k_http_status_service_unavailable;
            res.set_content(R"({"status":"NOT_SERVING"})", "application/json");
        }
    });

    router.get("/health/ready", [hm](const httplib::Request&, httplib::Response& res) {
        if (hm && hm->is_ready() && hm->evaluate_readiness()) {
            res.status = k_http_status_ok;
            res.set_content(R"({"status":"SERVING"})", "application/json");
        } else {
            res.status = k_http_status_service_unavailable;
            res.set_content(R"({"status":"NOT_SERVING"})", "application/json");
        }
    });
}

void GatewayRouteRegistrar::register_auth_routes(Router& router) {
    auth_proxy_->register_routes(router);

    // Route aliases for backward compatibility and canonical REST endpoints
    auto proxy = auth_proxy_;
    router.get_authenticated("/api/v1/auth/me",
                             [proxy](const httplib::Request& req, httplib::Response& res,
                                     const AuthenticatedContext& ctx) { proxy->handle_get_me(req, res, ctx); });

    router.post_authenticated(
        "/api/v1/auth/device/register",
        [proxy](const httplib::Request& req, httplib::Response& res, const AuthenticatedContext& ctx) {
            proxy->handle_register_device(req, res, ctx);
        });

    router.post_authenticated("/api/v1/auth/logout",
                              [proxy](const httplib::Request& req, httplib::Response& res,
                                      const AuthenticatedContext& ctx) { proxy->handle_revoke(req, res, ctx); });
}

void GatewayRouteRegistrar::register_stub_routes(Router& router) {
    auto stub_handler = [](const httplib::Request& req, httplib::Response& res, const AuthenticatedContext& /*ctx*/) {
        std::string request_id;
        if (const auto* rc = RequestContext::current()) {
            request_id = rc->request_id();
        } else if (req.has_header("X-Request-ID")) {
            request_id = req.get_header_value("X-Request-ID");
        } else if (req.has_header("X-Request-Id")) {
            request_id = req.get_header_value("X-Request-Id");
        }
        ErrorMapper::write_error(res, 501, "NOT_IMPLEMENTED",
                                 "Service route under construction in subsequent milestone", request_id);
    };

    // Messaging microservice stubs (M3 / MSG-005)
    router.post_authenticated("/api/v1/messages/send", stub_handler);
    router.get_authenticated("/api/v1/messages/inbox", stub_handler);
    router.get_authenticated("/api/v1/messages/conversations", stub_handler);

    // Files microservice stubs (M5 / GW-010)
    router.post_authenticated("/api/v1/files/upload", stub_handler);
    router.get_authenticated("/api/v1/files/download", stub_handler);

    // Audit microservice stubs (M6 / AUDIT-004)
    router.get_authenticated("/api/v1/audit/events", stub_handler);
}

} // namespace securecloud::gateway::http
