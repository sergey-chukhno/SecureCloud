#pragma once

#include "securecloud/configuration/secret_string.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace securecloud::client::application {

struct ClientConfig {
    std::string gateway_url{"https://127.0.0.1"};
    uint16_t gateway_port{8443};
    std::string tls_ca_cert_path{};
    std::chrono::milliseconds connect_timeout_ms{5000};
    std::chrono::milliseconds request_timeout_ms{15000};
    std::string database_path{};
    std::string keychain_service_id{"securecloud.desktop"};
    std::chrono::milliseconds heartbeat_interval_ms{30000};
    std::chrono::milliseconds sync_poll_interval_ms{5000};
    uint32_t max_retry_attempts{3};
    securecloud::common::configuration::SecretString auth_token{};

    static ClientConfig create_default();
    static ClientConfig from_environment();

    [[nodiscard]] std::vector<std::string> validate() const;
    [[nodiscard]] bool is_valid() const noexcept;
    [[nodiscard]] std::string to_safe_string() const;
};

} // namespace securecloud::client::application

