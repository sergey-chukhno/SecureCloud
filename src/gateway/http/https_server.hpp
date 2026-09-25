#pragma once

#include "gateway_config.hpp"
#include "http/http_server.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace httplib {
class SSLServer;
struct Request;
struct Response;
} // namespace httplib

namespace securecloud::gateway::http {

/// External HTTPS/TLS 1.3 server engine wrapping httplib::SSLServer (GW-002-TC-03).
class HttpsServer {
  public:
    explicit HttpsServer(const GatewayConfig& config);
    HttpsServer(std::string host, uint16_t port, GatewayTlsConfig tls_config, uint32_t threads = 4,
                uint64_t max_payload_bytes = 10485760,
                std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));
    ~HttpsServer();

    HttpsServer(const HttpsServer&) = delete;
    HttpsServer& operator=(const HttpsServer&) = delete;
    HttpsServer(HttpsServer&&) noexcept;
    HttpsServer& operator=(HttpsServer&&) noexcept;

    [[nodiscard]] bool start_async();
    [[nodiscard]] bool start(const std::string& host, uint16_t port);
    void stop() noexcept;
    void wait_until_ready() const;

    [[nodiscard]] ServerState state() const noexcept;
    [[nodiscard]] bool is_running() const noexcept;
    [[nodiscard]] uint16_t bound_port() const noexcept;
    [[nodiscard]] const std::string& listen_address() const noexcept;
    [[nodiscard]] const GatewayTlsConfig& tls_config() const;

    void get(const std::string& pattern, HttpHandler handler);
    void post(const std::string& pattern, HttpHandler handler);
    void put(const std::string& pattern, HttpHandler handler);
    void del(const std::string& pattern, HttpHandler handler);

    [[nodiscard]] httplib::SSLServer& raw_server() noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace securecloud::gateway::http
