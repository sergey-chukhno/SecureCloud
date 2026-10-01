#pragma once

#include "http/auth/authenticated_context.hpp"
#include "http/errors/error_mapper.hpp"
#include "http/middleware/middleware.hpp"

#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace httplib {
struct Request;
struct Response;
} // namespace httplib

namespace securecloud::gateway::http {

class HttpServer;
class HttpsServer;
class RequestContext;

using RouteHandler = std::function<void(const httplib::Request&, httplib::Response&)>;
using AuthenticatedRouteHandler =
    std::function<void(const httplib::Request&, httplib::Response&, const AuthenticatedContext&)>;

class Router {
  public:
    Router();
    ~Router() = default;

    void add_route(std::string method, std::string path, RouteHandler handler);
    void get(std::string path, RouteHandler handler);
    void post(std::string path, RouteHandler handler);
    void put(std::string path, RouteHandler handler);
    void del(std::string path, RouteHandler handler);

    void add_authenticated_route(std::string method, std::string path, AuthenticatedRouteHandler handler);
    void get_authenticated(std::string path, AuthenticatedRouteHandler handler);
    void post_authenticated(std::string path, AuthenticatedRouteHandler handler);
    void put_authenticated(std::string path, AuthenticatedRouteHandler handler);
    void del_authenticated(std::string path, AuthenticatedRouteHandler handler);

    [[nodiscard]] static std::optional<AuthenticatedContext> get_authenticated_context(const httplib::Request& req);

    /// Retrieves the active RequestContext bound to the current executing request thread, or nullptr if none
    [[nodiscard]] static const RequestContext* current_request_context() noexcept;

    /// Retrieves the active AuthenticatedContext bound to the current executing request thread
    [[nodiscard]] static std::optional<AuthenticatedContext> current_authenticated_context() noexcept;

    void use(std::shared_ptr<Middleware> middleware);

    void handle(const httplib::Request& req, httplib::Response& res);

    void register_into(HttpServer& server);
    void register_into(HttpsServer& server);

    [[nodiscard]] size_t route_count() const noexcept { return routes_.size(); }

  private:
    void dispatch_route(const httplib::Request& req, httplib::Response& res);

    MiddlewarePipeline pipeline_;
    std::map<std::pair<std::string, std::string>, RouteHandler> routes_;
    std::map<std::string, std::vector<std::string>> path_methods_;
};

} // namespace securecloud::gateway::http
