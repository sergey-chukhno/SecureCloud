#pragma once

#include "gateway_config.hpp"
#include "http/http_server.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

namespace securecloud::gateway::http {

/// HTTP Redirect Server that redirects all cleartext HTTP traffic to HTTPS with HTTP 308 Permanent Redirect
/// (GW-002-T05).
class HttpRedirectServer {
  public:
    explicit HttpRedirectServer(const GatewayConfig& config);
    HttpRedirectServer(std::string host, uint16_t http_port, uint16_t https_port, uint32_t threads = 2,
                       std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));
    ~HttpRedirectServer();

    HttpRedirectServer(const HttpRedirectServer&) = delete;
    HttpRedirectServer& operator=(const HttpRedirectServer&) = delete;
    HttpRedirectServer(HttpRedirectServer&&) noexcept;
    HttpRedirectServer& operator=(HttpRedirectServer&&) noexcept;

    [[nodiscard]] bool start_async();
    void stop() noexcept;
    void wait_until_ready() const;

    [[nodiscard]] ServerState state() const noexcept;
    [[nodiscard]] bool is_running() const noexcept;
    [[nodiscard]] uint16_t bound_port() const noexcept;
    [[nodiscard]] uint16_t https_target_port() const noexcept;
    [[nodiscard]] const std::string& listen_address() const noexcept;

    /// Formats the target HTTPS redirect URL for a given request Host header and target URI.
    [[nodiscard]] std::string build_redirect_url(const std::string& host_header, const std::string& target_path) const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace securecloud::gateway::http
