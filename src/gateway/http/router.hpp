#pragma once

#include "http/error_mapper.hpp"
#include "http/middleware.hpp"

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace httplib {
struct Request;
struct Response;
} // namespace httplib

namespace securecloud::gateway::http {

class HttpServer;

using RouteHandler = std::function<void(const httplib::Request&, httplib::Response&)>;

class Router {
  public:
    Router();
    ~Router() = default;

    void add_route(std::string method, std::string path, RouteHandler handler);
    void get(std::string path, RouteHandler handler);
    void post(std::string path, RouteHandler handler);
    void put(std::string path, RouteHandler handler);
    void del(std::string path, RouteHandler handler);

    void use(std::shared_ptr<Middleware> middleware);

    void handle(const httplib::Request& req, httplib::Response& res);

    void register_into(HttpServer& server);

    [[nodiscard]] size_t route_count() const noexcept { return routes_.size(); }

  private:
    void dispatch_route(const httplib::Request& req, httplib::Response& res);

    MiddlewarePipeline pipeline_;
    std::map<std::pair<std::string, std::string>, RouteHandler> routes_;
    std::map<std::string, std::vector<std::string>> path_methods_;
};

} // namespace securecloud::gateway::http
