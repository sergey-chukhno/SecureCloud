#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace httplib {
struct Request;
struct Response;
} // namespace httplib

namespace securecloud::gateway::http {

using NextHandler = std::function<void(const httplib::Request&, httplib::Response&)>;

class Middleware {
  public:
    virtual ~Middleware() = default;
    virtual void process(const httplib::Request& req, httplib::Response& res, const NextHandler& next) = 0;
};

class MiddlewarePipeline {
  public:
    void use(std::shared_ptr<Middleware> middleware);
    void execute(const httplib::Request& req, httplib::Response& res, const NextHandler& terminal_handler) const;

    [[nodiscard]] size_t size() const noexcept { return middlewares_.size(); }

  private:
    std::vector<std::shared_ptr<Middleware>> middlewares_;
};

class RequestIdMiddleware : public Middleware {
  public:
    static constexpr const char* k_request_id_header = "X-Request-Id";

    [[nodiscard]] static std::string generate_uuid_v4();

    void process(const httplib::Request& req, httplib::Response& res, const NextHandler& next) override;
};

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
