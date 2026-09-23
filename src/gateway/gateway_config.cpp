#include "gateway_config.hpp"

#include "securecloud/configuration/config_parser.hpp"

#include <exception>
#include <optional>
#include <string>
#include <string_view>

namespace securecloud::gateway {

namespace {

constexpr uint16_t k_default_gateway_grpc_port = 50051;
constexpr uint16_t k_default_http_port = 8080;
constexpr uint16_t k_min_port = 1;
constexpr uint16_t k_max_port = 65535;

constexpr uint64_t k_default_max_payload_bytes = 10485760; // 10 MB
constexpr uint64_t k_min_max_payload_bytes = 1024;         // 1 KB
constexpr uint64_t k_max_max_payload_bytes = 104857600;    // 100 MB

constexpr uint64_t k_default_request_timeout_ms = 5000;
constexpr uint64_t k_min_request_timeout_ms = 100;
constexpr uint64_t k_max_request_timeout_ms = 60000;

constexpr uint16_t k_default_server_threads = 4;
constexpr uint16_t k_min_server_threads = 1;
constexpr uint16_t k_max_server_threads = 128;

void parse_payload_bytes(const std::string& key, const std::string& value, uint64_t& out_bytes,
                         common::configuration::ValidationResult& out_errors) {
    if (value.empty()) {
        out_errors.add_error(key, "payload bytes must not be empty");
        return;
    }
    try {
        size_t idx = 0;
        uint64_t val = std::stoull(value, &idx);
        if (idx != value.size()) {
            out_errors.add_error(key, "invalid unsigned integer: " + value);
            return;
        }
        if (val < k_min_max_payload_bytes || val > k_max_max_payload_bytes) {
            out_errors.add_error(key, "value " + value + " out of allowed range [" +
                                          std::to_string(k_min_max_payload_bytes) + ".." +
                                          std::to_string(k_max_max_payload_bytes) + "]");
            return;
        }
        out_bytes = val;
    } catch (const std::exception&) {
        out_errors.add_error(key, "invalid unsigned integer or out of range: " + value);
    }
}

void parse_endpoint(std::string_view key, const std::optional<std::string>& opt_val, std::string& target,
                    common::configuration::ValidationResult& out_errors) {
    if (!opt_val.has_value()) {
        return;
    }
    if (opt_val.value().empty()) {
        out_errors.add_error(std::string(key), "endpoint must not be empty");
        return;
    }
    auto parsed = common::configuration::ConfigParser::parse_string(key, opt_val.value(), out_errors, false);
    if (parsed.has_value()) {
        target = parsed.value();
    }
}

void load_http_config(GatewayConfig& config, const common::configuration::ConfigurationSource& source,
                      common::configuration::ValidationResult& out_errors) {
    // 1. HTTP Listen Host / Address
    auto http_host = source.get("SECURECLOUD_GATEWAY_HTTP_HOST");
    if (!http_host.has_value()) {
        http_host = source.get("SECURECLOUD_GATEWAY_HTTP_LISTEN_ADDRESS");
    }
    if (http_host.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_GATEWAY_HTTP_HOST",
                                                                        http_host.value(), out_errors, false);
        if (parsed.has_value()) {
            config.http_listen_address = parsed.value();
        }
    }

    // 2. HTTP Listen Port
    auto http_port = source.get("SECURECLOUD_GATEWAY_HTTP_PORT");
    if (http_port.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint16(
            "SECURECLOUD_GATEWAY_HTTP_PORT", http_port.value(), out_errors, k_min_port, k_max_port);
        if (parsed.has_value()) {
            config.http_listen_port = parsed.value();
        }
    } else {
        config.http_listen_port = k_default_http_port;
    }

    // 3. Max Payload Bytes
    auto max_payload = source.get("SECURECLOUD_GATEWAY_MAX_PAYLOAD_BYTES");
    if (max_payload.has_value()) {
        parse_payload_bytes("SECURECLOUD_GATEWAY_MAX_PAYLOAD_BYTES", max_payload.value(), config.max_payload_bytes,
                            out_errors);
    } else {
        config.max_payload_bytes = k_default_max_payload_bytes;
    }

    // 4. Request Timeout (ms)
    auto req_timeout = source.get("SECURECLOUD_GATEWAY_REQUEST_TIMEOUT_MS");
    if (req_timeout.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_duration_ms(
            "SECURECLOUD_GATEWAY_REQUEST_TIMEOUT_MS", req_timeout.value(), out_errors, k_min_request_timeout_ms,
            k_max_request_timeout_ms);
        if (parsed.has_value()) {
            config.request_timeout_ms = parsed.value();
        }
    } else {
        config.request_timeout_ms = std::chrono::milliseconds(k_default_request_timeout_ms);
    }

    // 5. Server Threads
    auto threads_val = source.get("SECURECLOUD_GATEWAY_SERVER_THREADS");
    if (threads_val.has_value()) {
        auto parsed =
            common::configuration::ConfigParser::parse_uint16("SECURECLOUD_GATEWAY_SERVER_THREADS", threads_val.value(),
                                                              out_errors, k_min_server_threads, k_max_server_threads);
        if (parsed.has_value()) {
            config.server_threads = parsed.value();
        }
    } else {
        config.server_threads = k_default_server_threads;
    }
}

void load_downstream_endpoints(GatewayConfig& config, const common::configuration::ConfigurationSource& source,
                               common::configuration::ValidationResult& out_errors) {
    parse_endpoint("SECURECLOUD_GATEWAY_AUTH_ENDPOINT", source.get("SECURECLOUD_GATEWAY_AUTH_ENDPOINT"),
                   config.auth_endpoint, out_errors);
    parse_endpoint("SECURECLOUD_GATEWAY_MESSAGING_ENDPOINT", source.get("SECURECLOUD_GATEWAY_MESSAGING_ENDPOINT"),
                   config.messaging_endpoint, out_errors);
    parse_endpoint("SECURECLOUD_GATEWAY_FILES_ENDPOINT", source.get("SECURECLOUD_GATEWAY_FILES_ENDPOINT"),
                   config.files_endpoint, out_errors);
    parse_endpoint("SECURECLOUD_GATEWAY_AUDIT_ENDPOINT", source.get("SECURECLOUD_GATEWAY_AUDIT_ENDPOINT"),
                   config.audit_endpoint, out_errors);
}

} // namespace

std::string GatewayConfig::http_listen_endpoint() const {
    return http_listen_address + ":" + std::to_string(http_listen_port);
}

GatewayConfig GatewayConfig::load(const common::configuration::ConfigurationSource& source,
                                  common::configuration::ValidationResult& out_errors) {
    GatewayConfig config;
    config.common = common::configuration::CommonServiceConfig::load(source, "gateway", "Gateway Service",
                                                                     k_default_gateway_grpc_port, out_errors);

    load_http_config(config, source, out_errors);
    load_downstream_endpoints(config, source, out_errors);

    // Peer probe resolution (canonical service prefix > legacy fallback)
    config.peer_probe_target = source.get("SECURECLOUD_GATEWAY_PEER_PROBE_TARGET")
                                   .value_or(source.get("SECURECLOUD_PEER_PROBE_TARGET").value_or(""));

    config.peer_probe_name = source.get("SECURECLOUD_GATEWAY_PEER_PROBE_NAME")
                                 .value_or(source.get("SECURECLOUD_PEER_PROBE_NAME").value_or(""));

    return config;
}

} // namespace securecloud::gateway
