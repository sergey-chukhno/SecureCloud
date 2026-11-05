#include "application/client_config.hpp"

#include <cstdlib>
#include <sstream>

namespace securecloud::client::application {

namespace {

std::string get_env_or_default(const char* name, std::string default_val) {
    if (const char* val = std::getenv(name); val != nullptr && *val != '\0') {
        return std::string(val);
    }
    return default_val;
}

uint64_t get_env_uint64_or_default(const char* name, uint64_t default_val) {
    if (const char* val = std::getenv(name); val != nullptr && *val != '\0') {
        try {
            return std::stoull(val);
        } catch (...) {
            return default_val;
        }
    }
    return default_val;
}

} // namespace

ClientConfig ClientConfig::create_default() {
    return ClientConfig{};
}

ClientConfig ClientConfig::from_environment() {
    ClientConfig config;
    config.gateway_url = get_env_or_default("SECURECLOUD_GATEWAY_URL", config.gateway_url);

    const uint64_t port = get_env_uint64_or_default("SECURECLOUD_GATEWAY_PORT", config.gateway_port);
    if (port > 0 && port <= 65535) {
        config.gateway_port = static_cast<uint16_t>(port);
    }

    config.tls_ca_cert_path = get_env_or_default("SECURECLOUD_TLS_CA_CERT_PATH", config.tls_ca_cert_path);

    const uint64_t connect_timeout = get_env_uint64_or_default(
        "SECURECLOUD_CONNECT_TIMEOUT_MS", static_cast<uint64_t>(config.connect_timeout_ms.count()));
    config.connect_timeout_ms = std::chrono::milliseconds(connect_timeout);

    const uint64_t request_timeout = get_env_uint64_or_default(
        "SECURECLOUD_REQUEST_TIMEOUT_MS", static_cast<uint64_t>(config.request_timeout_ms.count()));
    config.request_timeout_ms = std::chrono::milliseconds(request_timeout);

    config.database_path = get_env_or_default("SECURECLOUD_DATABASE_PATH", config.database_path);
    config.keychain_service_id = get_env_or_default("SECURECLOUD_KEYCHAIN_SERVICE_ID", config.keychain_service_id);

    const uint64_t heartbeat = get_env_uint64_or_default("SECURECLOUD_HEARTBEAT_INTERVAL_MS",
                                                         static_cast<uint64_t>(config.heartbeat_interval_ms.count()));
    config.heartbeat_interval_ms = std::chrono::milliseconds(heartbeat);

    const uint64_t sync_poll = get_env_uint64_or_default("SECURECLOUD_SYNC_POLL_INTERVAL_MS",
                                                         static_cast<uint64_t>(config.sync_poll_interval_ms.count()));
    config.sync_poll_interval_ms = std::chrono::milliseconds(sync_poll);

    const uint64_t retries = get_env_uint64_or_default("SECURECLOUD_MAX_RETRY_ATTEMPTS", config.max_retry_attempts);
    if (retries <= UINT32_MAX) {
        config.max_retry_attempts = static_cast<uint32_t>(retries);
    }

    if (const char* token = std::getenv("SECURECLOUD_AUTH_TOKEN"); token != nullptr && *token != '\0') {
        config.auth_token = securecloud::common::configuration::SecretString(token);
    }

    return config;
}

std::vector<std::string> ClientConfig::validate() const {
    std::vector<std::string> errors;

    if (gateway_url.empty()) {
        errors.emplace_back("gateway_url cannot be empty");
    } else if (gateway_url.rfind("https://", 0) != 0 && gateway_url.rfind("http://", 0) != 0) {
        errors.emplace_back("gateway_url must start with https:// or http://");
    }

    if (gateway_port == 0) {
        errors.emplace_back("gateway_port must be non-zero");
    }

    if (connect_timeout_ms.count() <= 0) {
        errors.emplace_back("connect_timeout_ms must be greater than zero");
    }

    if (request_timeout_ms.count() <= 0) {
        errors.emplace_back("request_timeout_ms must be greater than zero");
    }

    if (request_timeout_ms < connect_timeout_ms) {
        errors.emplace_back("request_timeout_ms must be greater than or equal to connect_timeout_ms");
    }

    if (heartbeat_interval_ms.count() <= 0) {
        errors.emplace_back("heartbeat_interval_ms must be greater than zero");
    }

    if (sync_poll_interval_ms.count() <= 0) {
        errors.emplace_back("sync_poll_interval_ms must be greater than zero");
    }

    if (max_retry_attempts == 0) {
        errors.emplace_back("max_retry_attempts must be greater than zero");
    }

    if (keychain_service_id.empty()) {
        errors.emplace_back("keychain_service_id cannot be empty");
    }

    return errors;
}

bool ClientConfig::is_valid() const noexcept {
    return validate().empty();
}

std::string ClientConfig::to_safe_string() const {
    std::ostringstream oss;
    oss << "ClientConfig {\n"
        << "  gateway_url: " << gateway_url << "\n"
        << "  gateway_port: " << gateway_port << "\n"
        << "  tls_ca_cert_path: " << (tls_ca_cert_path.empty() ? "[NONE]" : tls_ca_cert_path) << "\n"
        << "  connect_timeout_ms: " << connect_timeout_ms.count() << "ms\n"
        << "  request_timeout_ms: " << request_timeout_ms.count() << "ms\n"
        << "  database_path: " << (database_path.empty() ? "[DEFAULT]" : database_path) << "\n"
        << "  keychain_service_id: " << keychain_service_id << "\n"
        << "  heartbeat_interval_ms: " << heartbeat_interval_ms.count() << "ms\n"
        << "  sync_poll_interval_ms: " << sync_poll_interval_ms.count() << "ms\n"
        << "  max_retry_attempts: " << max_retry_attempts << "\n"
        << "  auth_token: " << (auth_token.empty() ? "[EMPTY]" : "[REDACTED]") << "\n"
        << "}";
    return oss.str();
}

} // namespace securecloud::client::application
