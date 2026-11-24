#include "application/client_config.hpp"

#include <cctype>
#include <cstdlib>
#include <sstream>

namespace securecloud::client::application {

namespace {

std::string to_lower_ascii(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    for (const char ch : sv) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return out;
}

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

bool get_env_bool_or_default(const char* name, bool default_val) {
    if (const char* val = std::getenv(name); val != nullptr && *val != '\0') {
        const std::string lower = to_lower_ascii(val);
        if (lower == "1" || lower == "true" || lower == "yes" || lower == "on") {
            return true;
        }
        if (lower == "0" || lower == "false" || lower == "no" || lower == "off") {
            return false;
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

    config.use_live_gateway_transport =
        get_env_bool_or_default("SECURECLOUD_USE_LIVE_GATEWAY", config.use_live_gateway_transport);

    if (const char* raw_proxy_type = std::getenv("SECURECLOUD_PROXY_TYPE");
        raw_proxy_type != nullptr && *raw_proxy_type != '\0') {
        if (const auto parsed_type = domain::proxy_type_from_string(raw_proxy_type); parsed_type.has_value()) {
            config.proxy_type = *parsed_type;
        }
    }

    config.proxy_host = get_env_or_default("SECURECLOUD_PROXY_HOST", config.proxy_host);

    const uint64_t raw_proxy_port = get_env_uint64_or_default("SECURECLOUD_PROXY_PORT", config.proxy_port);
    if (raw_proxy_port > 0 && raw_proxy_port <= 65535) {
        config.proxy_port = static_cast<uint16_t>(raw_proxy_port);
    }

    config.proxy_username = get_env_or_default("SECURECLOUD_PROXY_USER", config.proxy_username);

    if (const char* proxy_pass = std::getenv("SECURECLOUD_PROXY_PASS"); proxy_pass != nullptr && *proxy_pass != '\0') {
        config.proxy_password = securecloud::common::configuration::SecretString(proxy_pass);
    }

    if (const char* pin = std::getenv("SECURECLOUD_TLS_PIN_SPKI_SHA256"); pin != nullptr && *pin != '\0') {
        config.pinned_tls_spki_sha256 = domain::normalize_hex_lower(pin);
    }

    config.enforce_tls_pinning = get_env_bool_or_default("SECURECLOUD_TLS_ENFORCE_PINNING", config.enforce_tls_pinning);

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

    if (proxy_type != domain::ProxyType::None) {
        domain::ProxyConfig proxy;
        proxy.type = proxy_type;
        proxy.host = proxy_host;
        proxy.port = proxy_port;
        proxy.username = proxy_username;
        for (auto& err : proxy.validate()) {
            errors.push_back(std::move(err));
        }
    }

    if (!pinned_tls_spki_sha256.empty() && !domain::is_valid_sha256_hex(pinned_tls_spki_sha256)) {
        errors.emplace_back("pinned_tls_spki_sha256 must be a valid 64-character SHA-256 hex digest");
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
        << "  use_live_gateway_transport: " << (use_live_gateway_transport ? "true" : "false") << "\n"
        << "  proxy_type: " << domain::to_string(proxy_type) << "\n"
        << "  proxy_host: " << (proxy_host.empty() ? "[NONE]" : proxy_host) << "\n"
        << "  proxy_port: " << proxy_port << "\n"
        << "  proxy_username: " << (proxy_username.empty() ? "[NONE]" : proxy_username) << "\n"
        << "  proxy_password: " << (proxy_password.empty() ? "[EMPTY]" : "[REDACTED]") << "\n"
        << "  pinned_tls_spki_sha256: " << (pinned_tls_spki_sha256.empty() ? "[NONE]" : pinned_tls_spki_sha256) << "\n"
        << "  enforce_tls_pinning: " << (enforce_tls_pinning ? "true" : "false") << "\n"
        << "}";
    return oss.str();
}

} // namespace securecloud::client::application
