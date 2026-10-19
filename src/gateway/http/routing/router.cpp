#include "http/routing/router.hpp"

#include "http/auth/authentication_middleware.hpp"
#include "http/auth/request_context.hpp"
#include "http/middleware/request_id_middleware.hpp"
#include "http/server/http_server.hpp"
#include "http/server/https_server.hpp"

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

bool is_parameterized_pattern(std::string_view path) {
    return path.find(':') != std::string_view::npos || path.find('{') != std::string_view::npos;
}

std::pair<std::regex, std::vector<std::string>> compile_pattern(std::string_view path) {
    std::string regex_str = "^";
    std::vector<std::string> param_names;
    size_t i = 0;
    while (i < path.size()) {
        if (path[i] == ':' && i + 1 < path.size() &&
            (std::isalnum(static_cast<unsigned char>(path[i + 1])) || path[i + 1] == '_')) {
            size_t start = i + 1;
            size_t end = start;
            while (end < path.size() && (std::isalnum(static_cast<unsigned char>(path[end])) || path[end] == '_')) {
                ++end;
            }
            param_names.emplace_back(path.substr(start, end - start));
            regex_str += "([^/]+)";
            i = end;
        } else if (path[i] == '{') {
            size_t end = path.find('}', i);
            if (end != std::string_view::npos) {
                param_names.emplace_back(path.substr(i + 1, end - (i + 1)));
                regex_str += "([^/]+)";
                i = end + 1;
            } else {
                regex_str += "\\{";
                ++i;
            }
        } else {
            char c = path[i];
            if (c == '.' || c == '+' || c == '?' || c == '*' || c == '^' || c == '$' || c == '(' || c == ')' ||
                c == '[' || c == ']' || c == '\\') {
                regex_str += '\\';
            }
            regex_str += c;
            ++i;
        }
    }
    regex_str += "$";
    return {std::regex(regex_str), std::move(param_names)};
}

} // namespace

Router::Router() {
    pipeline_.use(std::make_shared<RequestIdMiddleware>());
}

std::string Router::get_path_param(const httplib::Request& req, const std::string& name) {
    auto it = req.path_params.find(name);
    if (it != req.path_params.end()) {
        return it->second;
    }
    return "";
}

void Router::add_route(std::string method, std::string path, RouteHandler handler) {
    path_methods_[path].push_back(method);
    if (is_parameterized_pattern(path)) {
        auto [re, params] = compile_pattern(path);
        parameterized_routes_.push_back(ParameterizedRoute{
            .method = std::move(method),
            .raw_path = std::move(path),
            .param_names = std::move(params),
            .regex = std::move(re),
            .handler = std::move(handler),
        });
    } else {
        routes_[{std::move(method), std::move(path)}] = std::move(handler);
    }
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

void Router::add_authenticated_route(std::string method, std::string path, AuthenticatedRouteHandler handler) {
    add_route(std::move(method), std::move(path),
              [h = std::move(handler)](const httplib::Request& req, httplib::Response& res) {
                  auto ctx_opt = get_authenticated_context(req);
                  if (!ctx_opt.has_value()) {
                      std::string req_id = extract_request_id(res);
                      ErrorMapper::write_error(res, 401, "UNAUTHENTICATED",
                                               "Authenticated context missing from request execution scope", req_id);
                      return;
                  }
                  h(req, res, *ctx_opt);
              });
}

void Router::get_authenticated(std::string path, AuthenticatedRouteHandler handler) {
    add_authenticated_route("GET", std::move(path), std::move(handler));
}

void Router::post_authenticated(std::string path, AuthenticatedRouteHandler handler) {
    add_authenticated_route("POST", std::move(path), std::move(handler));
}

void Router::put_authenticated(std::string path, AuthenticatedRouteHandler handler) {
    add_authenticated_route("PUT", std::move(path), std::move(handler));
}

void Router::del_authenticated(std::string path, AuthenticatedRouteHandler handler) {
    add_authenticated_route("DELETE", std::move(path), std::move(handler));
}

std::optional<AuthenticatedContext> Router::get_authenticated_context(const httplib::Request& req) {
    if (const auto* req_ctx = RequestContext::current(); req_ctx != nullptr && req_ctx->is_authenticated()) {
        return req_ctx->authenticated_context();
    }
    return AuthenticationMiddleware::get_context(req);
}

const RequestContext* Router::current_request_context() noexcept {
    return RequestContext::current();
}

std::optional<AuthenticatedContext> Router::current_authenticated_context() noexcept {
    if (const auto* req_ctx = RequestContext::current(); req_ctx != nullptr && req_ctx->is_authenticated()) {
        return req_ctx->authenticated_context();
    }
    httplib::Request dummy_req;
    return AuthenticationMiddleware::get_context(dummy_req);
}

void Router::use(std::shared_ptr<Middleware> middleware) {
    pipeline_.use(std::move(middleware));
}

void Router::handle(const httplib::Request& req, httplib::Response& res) {
    pipeline_.execute(req, res, [this](const httplib::Request& r, httplib::Response& s) { dispatch_route(r, s); });
}

void Router::dispatch_route(const httplib::Request& req, httplib::Response& res) {
    try {
        // 1. Exact match fast path
        auto route_it = routes_.find({req.method, req.path});
        if (route_it != routes_.end()) {
            route_it->second(req, res);
            return;
        }

        // 2. Parameterized pattern match
        for (const auto& p_route : parameterized_routes_) {
            if (p_route.method == req.method || p_route.method == "*") {
                std::smatch matches;
                if (std::regex_match(req.path, matches, p_route.regex)) {
                    auto& mutable_req = const_cast<httplib::Request&>(req);
                    for (size_t i = 0; i < p_route.param_names.size() && (i + 1) < matches.size(); ++i) {
                        mutable_req.path_params[p_route.param_names[i]] = matches[i + 1].str();
                    }
                    p_route.handler(req, res);
                    return;
                }
            }
        }

        // 3. Method Not Allowed checks (exact paths)
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

        // 4. Method Not Allowed checks (parameterized paths)
        std::vector<std::string> param_allowed_methods;
        for (const auto& p_route : parameterized_routes_) {
            std::smatch matches;
            if (std::regex_match(req.path, matches, p_route.regex)) {
                param_allowed_methods.push_back(p_route.method);
            }
        }
        if (!param_allowed_methods.empty()) {
            std::string allow_header;
            for (size_t i = 0; i < param_allowed_methods.size(); ++i) {
                if (i > 0) {
                    allow_header += ", ";
                }
                allow_header += param_allowed_methods[i];
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
    auto handler = [this](const httplib::Request& req, httplib::Response& res) { this->handle(req, res); };
    server.raw_server().Get(".*", handler);
    server.raw_server().Post(".*", handler);
    server.raw_server().Put(".*", handler);
    server.raw_server().Delete(".*", handler);
    server.raw_server().Patch(".*", handler);
    server.raw_server().Options(".*", handler);
}

void Router::register_into(HttpsServer& server) {
    auto handler = [this](const httplib::Request& req, httplib::Response& res) { this->handle(req, res); };
    server.raw_server().Get(".*", handler);
    server.raw_server().Post(".*", handler);
    server.raw_server().Put(".*", handler);
    server.raw_server().Delete(".*", handler);
    server.raw_server().Patch(".*", handler);
    server.raw_server().Options(".*", handler);
}

} // namespace securecloud::gateway::http
