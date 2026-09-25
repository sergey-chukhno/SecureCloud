#pragma once

#include <functional>
#include <memory>
#include <vector>

namespace httplib {
struct Request;
struct Response;
} // namespace httplib

namespace securecloud::gateway::http {

using NextHandler = std::function<void(const httplib::Request&, httplib::Response&)>;

/// Abstract base interface for all HTTP/HTTPS request interceptors.
class Middleware {
  public:
    virtual ~Middleware() = default;
    virtual void process(const httplib::Request& req, httplib::Response& res, const NextHandler& next) = 0;
};

/// Sequential execution pipeline for chained middleware handlers.
class MiddlewarePipeline {
  public:
    void use(std::shared_ptr<Middleware> middleware);
    void execute(const httplib::Request& req, httplib::Response& res, const NextHandler& terminal_handler) const;

    [[nodiscard]] size_t size() const noexcept { return middlewares_.size(); }

  private:
    std::vector<std::shared_ptr<Middleware>> middlewares_;
};

} // namespace securecloud::gateway::http
