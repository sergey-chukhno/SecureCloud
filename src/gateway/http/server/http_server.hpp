#pragma once

#include "gateway_config.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace httplib {
class Server;
struct Request;
struct Response;
} // namespace httplib

namespace securecloud::gateway::http {

enum class ServerState { Stopped, Running, Draining };

using HttpHandler = std::function<void(const httplib::Request&, httplib::Response&)>;

class HttpServer {
  public:
    explicit HttpServer(const GatewayConfig& config);
    HttpServer(std::string host, uint16_t port, uint32_t threads = 4, uint64_t max_payload_bytes = 10485760,
               std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));
    ~HttpServer();

    HttpServer(const HttpServer&) = delete;
    HttpServer& operator=(const HttpServer&) = delete;
    HttpServer(HttpServer&&) noexcept;
    HttpServer& operator=(HttpServer&&) noexcept;

    [[nodiscard]] bool start_async();
    void stop() noexcept;
    void wait_until_ready() const;

    [[nodiscard]] ServerState state() const noexcept;
    [[nodiscard]] bool is_running() const noexcept;
    [[nodiscard]] uint16_t bound_port() const noexcept;
    [[nodiscard]] const std::string& listen_address() const noexcept;

    void get(const std::string& pattern, HttpHandler handler);
    void post(const std::string& pattern, HttpHandler handler);
    void put(const std::string& pattern, HttpHandler handler);
    void del(const std::string& pattern, HttpHandler handler);

    [[nodiscard]] httplib::Server& raw_server() noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace securecloud::gateway::http
