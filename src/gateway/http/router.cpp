#include "http/router.hpp"

#include "http/http_server.hpp"
#include "http/https_server.hpp"
#include "http/request_id_middleware.hpp"

#include <exception>
#include <httplib.h>
#include <memory>
#include <string>
#include <utility>

namespace securecloud::gateway::http {
namespace {

constexpr int k_status_not_found = 404;
constexpr int k_status_method_not_allowed = 405;
constexpr int k_status_internal_server_error = 500;

std::string extract_request_id(const httplib::Response& res) {
    if (res.has_header(RequestIdMiddleware::k_request_id_header)) {
        return res.get_header_value(RequestIdMiddleware::k_request_id_header);
    }
    return "";
}

} // namespace

Router::Router() {
    pipeline_.use(std::make_shared<RequestIdMiddleware>());
}

void Router::add_route(std::string method, std::string path, RouteHandler handler) {
    path_methods_[path].push_back(method);
    routes_[{std::move(method), std::move(path)}] = std::move(handler);
}

void Router::get(std::string path, RouteHandler handler) {
    add_route("GET", std::move(path), std::move(handler));
}

void Router::post(std::string path, RouteHandler handler) {
    add_route("POST", std::move(path), std::move(handler));
}

void Router::put(std::string path, RouteHandler handler) {
    add_route("PUT", std::move(path), std::move(handler));
}

void Router::del(std::string path, RouteHandler handler) {
    add_route("DELETE", std::move(path), std::move(handler));
}

void Router::use(std::shared_ptr<Middleware> middleware) {
    pipeline_.use(std::move(middleware));
}

void Router::handle(const httplib::Request& req, httplib::Response& res) {
    pipeline_.execute(req, res, [this](const httplib::Request& r, httplib::Response& s) { dispatch_route(r, s); });
}

void Router::dispatch_route(const httplib::Request& req, httplib::Response& res) {
    try {
        auto route_it = routes_.find({req.method, req.path});
        if (route_it != routes_.end()) {
            route_it->second(req, res);
            return;
        }

        auto path_it = path_methods_.find(req.path);
        if (path_it != path_methods_.end()) {
            std::string allow_header;
            for (size_t i = 0; i < path_it->second.size(); ++i) {
                if (i > 0) {
                    allow_header += ", ";
                }
                allow_header += path_it->second[i];
            }
            res.set_header("Allow", allow_header);
            ErrorMapper::write_error(res, k_status_method_not_allowed, "METHOD_NOT_ALLOWED",
                                     "Method not allowed for requested path", extract_request_id(res));
            return;
        }

        ErrorMapper::write_error(res, k_status_not_found, "NOT_FOUND", "Resource not found", extract_request_id(res));
    } catch (const std::exception&) {
        ErrorMapper::write_error(res, k_status_internal_server_error, "INTERNAL_ERROR", "An internal error occurred",
                                 extract_request_id(res));
    } catch (...) {
        ErrorMapper::write_error(res, k_status_internal_server_error, "INTERNAL_ERROR",
                                 "An unknown internal error occurred", extract_request_id(res));
    }
}

void Router::register_into(HttpServer& server) {
    server.raw_server().set_pre_routing_handler([this](const httplib::Request& req, httplib::Response& res) {
        this->handle(req, res);
        return httplib::Server::HandlerResponse::Handled;
    });
}

void Router::register_into(HttpsServer& server) {
    server.raw_server().set_pre_routing_handler([this](const httplib::Request& req, httplib::Response& res) {
        this->handle(req, res);
        return httplib::Server::HandlerResponse::Handled;
    });
}

} // namespace securecloud::gateway::http
