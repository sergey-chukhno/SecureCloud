#include "gateway_config.hpp"

#include "securecloud/configuration/config_parser.hpp"

#include <exception>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace securecloud::gateway {

namespace {

constexpr uint16_t k_default_gateway_grpc_port = 50051;
constexpr uint16_t k_default_http_port = 8080;
constexpr uint16_t k_default_https_port = 8443;
constexpr uint16_t k_min_port = 1;
constexpr uint16_t k_max_port = 65535;

constexpr const char* k_default_cert_path = "/etc/securecloud/certs/gateway/gateway.crt";
constexpr const char* k_default_key_path = "/etc/securecloud/certs/gateway/gateway.key";
constexpr const char* k_default_ca_path = "/etc/securecloud/certs/ca/ca.crt";
constexpr const char* k_default_min_tls_version = "TLSv1.3";
constexpr const char* k_default_cipher_suites =
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";

constexpr uint64_t k_default_max_payload_bytes = 10485760; // 10 MB
constexpr uint64_t k_min_max_payload_bytes = 1024;         // 1 KB
constexpr uint64_t k_max_max_payload_bytes = 104857600;    // 100 MB

constexpr size_t k_default_max_header_bytes = 16384; // 16 KB
constexpr size_t k_min_max_header_bytes = 1024;      // 1 KB
constexpr size_t k_max_max_header_bytes = 65536;     // 64 KB

constexpr size_t k_min_max_body_bytes = 1024;      // 1 KB
constexpr size_t k_max_max_body_bytes = 104857600; // 100 MB

constexpr uint32_t k_default_read_timeout_ms = 5000;
constexpr uint32_t k_min_read_timeout_ms = 100;
constexpr uint32_t k_max_read_timeout_ms = 60000;

constexpr uint32_t k_default_write_timeout_ms = 5000;
constexpr uint32_t k_min_write_timeout_ms = 100;
constexpr uint32_t k_max_write_timeout_ms = 60000;

constexpr uint32_t k_default_idle_timeout_ms = 30000;
constexpr uint32_t k_min_idle_timeout_ms = 100;
constexpr uint32_t k_max_idle_timeout_ms = 300000; // 5 minutes

constexpr size_t k_default_max_concurrent_connections = 1024;
constexpr size_t k_min_max_concurrent_connections = 1;
constexpr size_t k_max_max_concurrent_connections = 65536;

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

void parse_size_t(std::string_view key, const std::string& value, size_t& out_val,
                  common::configuration::ValidationResult& out_errors, size_t min_val, size_t max_val) {
    if (value.empty()) {
        out_errors.add_error(std::string(key), "value must not be empty");
        return;
    }
    try {
        size_t idx = 0;
        uint64_t val = std::stoull(value, &idx);
        if (idx != value.size()) {
            out_errors.add_error(std::string(key), "invalid unsigned integer: " + value);
            return;
        }
        if (val < min_val || val > max_val) {
            out_errors.add_error(std::string(key), "value " + value + " out of allowed range [" +
                                                       std::to_string(min_val) + ".." + std::to_string(max_val) + "]");
            return;
        }
        out_val = static_cast<size_t>(val);
    } catch (const std::exception&) {
        out_errors.add_error(std::string(key), "invalid unsigned integer or out of range: " + value);
    }
}

void parse_uint32(std::string_view key, const std::string& value, uint32_t& out_val,
                  common::configuration::ValidationResult& out_errors, uint32_t min_val, uint32_t max_val) {
    if (value.empty()) {
        out_errors.add_error(std::string(key), "value must not be empty");
        return;
    }
    try {
        size_t idx = 0;
        uint64_t val = std::stoull(value, &idx);
        if (idx != value.size()) {
            out_errors.add_error(std::string(key), "invalid unsigned integer: " + value);
            return;
        }
        if (val < min_val || val > max_val) {
            out_errors.add_error(std::string(key), "value " + value + " out of allowed range [" +
                                                       std::to_string(min_val) + ".." + std::to_string(max_val) + "]");
            return;
        }
        out_val = static_cast<uint32_t>(val);
    } catch (const std::exception&) {
        out_errors.add_error(std::string(key), "invalid unsigned integer or out of range: " + value);
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

    auto max_payload = source.get("SECURECLOUD_GATEWAY_MAX_PAYLOAD_BYTES");
    if (max_payload.has_value()) {
        parse_payload_bytes("SECURECLOUD_GATEWAY_MAX_PAYLOAD_BYTES", max_payload.value(), config.max_payload_bytes,
                            out_errors);
    } else {
        config.max_payload_bytes = k_default_max_payload_bytes;
    }

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

void resolve_tls_paths(GatewayConfig& config, const common::configuration::ConfigurationSource& source,
                       common::configuration::ValidationResult& out_errors) {
    auto cert_val = source.get("SECURECLOUD_GATEWAY_TLS_CERT_PATH");
    if (cert_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_GATEWAY_TLS_CERT_PATH",
                                                                        cert_val.value(), out_errors, true);
        if (parsed.has_value()) {
            config.tls.cert_path = parsed.value();
        }
    } else {
        config.tls.cert_path = k_default_cert_path;
    }

    auto key_val = source.get("SECURECLOUD_GATEWAY_TLS_KEY_PATH");
    if (key_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_GATEWAY_TLS_KEY_PATH",
                                                                        key_val.value(), out_errors, true);
        if (parsed.has_value()) {
            config.tls.key_path = parsed.value();
        }
    } else {
        config.tls.key_path = k_default_key_path;
    }

    auto ca_val = source.get("SECURECLOUD_GATEWAY_TLS_CA_PATH");
    if (!ca_val.has_value()) {
        ca_val = source.get("SECURECLOUD_GATEWAY_TLS_CA_CHAIN_PATH");
    }
    if (ca_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_GATEWAY_TLS_CA_PATH",
                                                                        ca_val.value(), out_errors, true);
        if (parsed.has_value()) {
            config.tls.ca_chain_path = parsed.value();
        }
    } else {
        config.tls.ca_chain_path = k_default_ca_path;
    }
}

void resolve_tls_protocol(GatewayConfig& config, const common::configuration::ConfigurationSource& source,
                          common::configuration::ValidationResult& out_errors) {
    auto https_port = source.get("SECURECLOUD_GATEWAY_HTTPS_PORT");
    if (https_port.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint16(
            "SECURECLOUD_GATEWAY_HTTPS_PORT", https_port.value(), out_errors, k_min_port, k_max_port);
        if (parsed.has_value()) {
            config.tls.https_listen_port = parsed.value();
        }
    } else {
        config.tls.https_listen_port = k_default_https_port;
    }

    auto min_tls = source.get("SECURECLOUD_GATEWAY_MIN_TLS_VERSION");
    if (min_tls.has_value()) {
        if (min_tls.value() != "TLSv1.3") {
            out_errors.add_error("SECURECLOUD_GATEWAY_MIN_TLS_VERSION", "insecure TLS version '" + min_tls.value() +
                                                                            "'; minimum allowed is strictly 'TLSv1.3'");
        } else {
            config.tls.min_tls_version = min_tls.value();
        }
    } else {
        config.tls.min_tls_version = k_default_min_tls_version;
    }

    auto ciphers = source.get("SECURECLOUD_GATEWAY_TLS_CIPHER_SUITES");
    if (ciphers.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_GATEWAY_TLS_CIPHER_SUITES",
                                                                        ciphers.value(), out_errors, false);
        if (parsed.has_value()) {
            config.tls.cipher_suites = parsed.value();
        }
    } else {
        config.tls.cipher_suites = k_default_cipher_suites;
    }
}

void validate_tls_cross_fields(const GatewayConfig& config, common::configuration::ValidationResult& out_errors,
                               bool validate_file_paths) {
    if (!config.tls.enabled) {
        return;
    }
    if (config.tls.https_listen_port == config.http_listen_port) {
        out_errors.add_error("SECURECLOUD_GATEWAY_HTTPS_PORT", "HTTPS listen port " +
                                                                   std::to_string(config.tls.https_listen_port) +
                                                                   " conflicts with HTTP listen port");
    }
    if (config.tls.https_listen_port == config.common.grpc_port) {
        out_errors.add_error("SECURECLOUD_GATEWAY_HTTPS_PORT", "HTTPS listen port " +
                                                                   std::to_string(config.tls.https_listen_port) +
                                                                   " conflicts with gRPC service port");
    }
    if (config.tls.cert_path.empty()) {
        out_errors.add_error("SECURECLOUD_GATEWAY_TLS_CERT_PATH",
                             "TLS certificate path cannot be empty when TLS is enabled");
    }
    if (config.tls.key_path.empty()) {
        out_errors.add_error("SECURECLOUD_GATEWAY_TLS_KEY_PATH",
                             "TLS private key path cannot be empty when TLS is enabled");
    }
    if (validate_file_paths) {
        config.validate_tls_paths(out_errors);
    }
}

void load_tls_config(GatewayConfig& config, const common::configuration::ConfigurationSource& source,
                     common::configuration::ValidationResult& out_errors, bool validate_file_paths) {
    auto tls_enabled = source.get("SECURECLOUD_GATEWAY_TLS_ENABLED");
    if (tls_enabled.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_bool("SECURECLOUD_GATEWAY_TLS_ENABLED",
                                                                      tls_enabled.value(), out_errors);
        if (parsed.has_value()) {
            config.tls.enabled = parsed.value();
        }
    } else {
        config.tls.enabled = true;
    }

    resolve_tls_paths(config, source, out_errors);
    resolve_tls_protocol(config, source, out_errors);
    validate_tls_cross_fields(config, out_errors, validate_file_paths);
}

void load_limits_config(GatewayConfig& config, const common::configuration::ConfigurationSource& source,
                        common::configuration::ValidationResult& out_errors) {
    auto max_hdr = source.get("SECURECLOUD_GATEWAY_MAX_HEADER_BYTES");
    if (max_hdr.has_value()) {
        parse_size_t("SECURECLOUD_GATEWAY_MAX_HEADER_BYTES", max_hdr.value(), config.limits.max_header_bytes,
                     out_errors, k_min_max_header_bytes, k_max_max_header_bytes);
    } else {
        config.limits.max_header_bytes = k_default_max_header_bytes;
    }

    auto max_body = source.get("SECURECLOUD_GATEWAY_MAX_BODY_BYTES");
    if (max_body.has_value()) {
        parse_size_t("SECURECLOUD_GATEWAY_MAX_BODY_BYTES", max_body.value(), config.limits.max_body_bytes, out_errors,
                     k_min_max_body_bytes, k_max_max_body_bytes);
        config.max_payload_bytes = config.limits.max_body_bytes;
    } else {
        config.limits.max_body_bytes = config.max_payload_bytes;
    }

    auto read_to = source.get("SECURECLOUD_GATEWAY_READ_TIMEOUT_MS");
    if (read_to.has_value()) {
        parse_uint32("SECURECLOUD_GATEWAY_READ_TIMEOUT_MS", read_to.value(), config.limits.read_timeout_ms, out_errors,
                     k_min_read_timeout_ms, k_max_read_timeout_ms);
    } else {
        config.limits.read_timeout_ms = k_default_read_timeout_ms;
    }

    auto write_to = source.get("SECURECLOUD_GATEWAY_WRITE_TIMEOUT_MS");
    if (write_to.has_value()) {
        parse_uint32("SECURECLOUD_GATEWAY_WRITE_TIMEOUT_MS", write_to.value(), config.limits.write_timeout_ms,
                     out_errors, k_min_write_timeout_ms, k_max_write_timeout_ms);
    } else {
        config.limits.write_timeout_ms = k_default_write_timeout_ms;
    }

    auto idle_to = source.get("SECURECLOUD_GATEWAY_IDLE_TIMEOUT_MS");
    if (idle_to.has_value()) {
        parse_uint32("SECURECLOUD_GATEWAY_IDLE_TIMEOUT_MS", idle_to.value(), config.limits.idle_timeout_ms, out_errors,
                     k_min_idle_timeout_ms, k_max_idle_timeout_ms);
    } else {
        config.limits.idle_timeout_ms = k_default_idle_timeout_ms;
    }

    auto max_conn = source.get("SECURECLOUD_GATEWAY_MAX_CONNECTIONS");
    if (!max_conn.has_value()) {
        max_conn = source.get("SECURECLOUD_GATEWAY_MAX_CONCURRENT_CONNECTIONS");
    }
    if (max_conn.has_value()) {
        parse_size_t("SECURECLOUD_GATEWAY_MAX_CONNECTIONS", max_conn.value(), config.limits.max_concurrent_connections,
                     out_errors, k_min_max_concurrent_connections, k_max_max_concurrent_connections);
    } else {
        config.limits.max_concurrent_connections = k_default_max_concurrent_connections;
    }
}

void load_deadlines_config(GatewayConfig& config, const common::configuration::ConfigurationSource& source,
                           common::configuration::ValidationResult& out_errors) {
    constexpr uint32_t k_min_timeout_val = 1;
    constexpr uint32_t k_max_upper_bound_timeout_val = 300000;

    auto max_to = source.get("SECURECLOUD_GATEWAY_TIMEOUT_MAX_MS");
    if (max_to.has_value()) {
        parse_uint32("SECURECLOUD_GATEWAY_TIMEOUT_MAX_MS", max_to.value(), config.deadlines.max_request_deadline_ms,
                     out_errors, k_min_timeout_val, k_max_upper_bound_timeout_val);
    } else {
        config.deadlines.max_request_deadline_ms = 10000;
    }

    auto min_to = source.get("SECURECLOUD_GATEWAY_TIMEOUT_MIN_MS");
    if (min_to.has_value()) {
        parse_uint32("SECURECLOUD_GATEWAY_TIMEOUT_MIN_MS", min_to.value(), config.deadlines.min_request_deadline_ms,
                     out_errors, k_min_timeout_val, config.deadlines.max_request_deadline_ms);
    } else {
        config.deadlines.min_request_deadline_ms = 50;
    }

    auto auth_to = source.get("SECURECLOUD_GATEWAY_TIMEOUT_AUTH_MS");
    if (auth_to.has_value()) {
        parse_uint32("SECURECLOUD_GATEWAY_TIMEOUT_AUTH_MS", auth_to.value(), config.deadlines.auth_timeout_ms,
                     out_errors, k_min_timeout_val, config.deadlines.max_request_deadline_ms);
    } else {
        config.deadlines.auth_timeout_ms = 1000;
    }

    auto msg_to = source.get("SECURECLOUD_GATEWAY_TIMEOUT_MESSAGING_MS");
    if (msg_to.has_value()) {
        parse_uint32("SECURECLOUD_GATEWAY_TIMEOUT_MESSAGING_MS", msg_to.value(), config.deadlines.messaging_timeout_ms,
                     out_errors, k_min_timeout_val, config.deadlines.max_request_deadline_ms);
    } else {
        config.deadlines.messaging_timeout_ms = 2000;
    }

    auto files_to = source.get("SECURECLOUD_GATEWAY_TIMEOUT_FILES_MS");
    if (files_to.has_value()) {
        parse_uint32("SECURECLOUD_GATEWAY_TIMEOUT_FILES_MS", files_to.value(),
                     config.deadlines.files_metadata_timeout_ms, out_errors, k_min_timeout_val,
                     config.deadlines.max_request_deadline_ms);
    } else {
        config.deadlines.files_metadata_timeout_ms = 2000;
    }

    auto audit_to = source.get("SECURECLOUD_GATEWAY_TIMEOUT_AUDIT_MS");
    if (audit_to.has_value()) {
        parse_uint32("SECURECLOUD_GATEWAY_TIMEOUT_AUDIT_MS", audit_to.value(), config.deadlines.audit_timeout_ms,
                     out_errors, k_min_timeout_val, config.deadlines.max_request_deadline_ms);
    } else {
        config.deadlines.audit_timeout_ms = 1000;
    }
}

void load_bulkhead_config(GatewayConfig& config, const common::configuration::ConfigurationSource& source,
                          common::configuration::ValidationResult& out_errors) {
    constexpr uint32_t k_min_bulkhead_val = 1;
    constexpr uint32_t k_max_bulkhead_val = 100000;

    auto auth_max = source.get("SECURECLOUD_GATEWAY_BULKHEAD_AUTH_MAX");
    if (auth_max.has_value()) {
        parse_uint32("SECURECLOUD_GATEWAY_BULKHEAD_AUTH_MAX", auth_max.value(), config.bulkhead.auth_max_concurrent,
                     out_errors, k_min_bulkhead_val, k_max_bulkhead_val);
    } else {
        config.bulkhead.auth_max_concurrent = 100;
    }

    auto msg_max = source.get("SECURECLOUD_GATEWAY_BULKHEAD_MESSAGING_MAX");
    if (msg_max.has_value()) {
        parse_uint32("SECURECLOUD_GATEWAY_BULKHEAD_MESSAGING_MAX", msg_max.value(),
                     config.bulkhead.messaging_max_concurrent, out_errors, k_min_bulkhead_val, k_max_bulkhead_val);
    } else {
        config.bulkhead.messaging_max_concurrent = 200;
    }

    auto files_max = source.get("SECURECLOUD_GATEWAY_BULKHEAD_FILES_MAX");
    if (files_max.has_value()) {
        parse_uint32("SECURECLOUD_GATEWAY_BULKHEAD_FILES_MAX", files_max.value(), config.bulkhead.files_max_concurrent,
                     out_errors, k_min_bulkhead_val, k_max_bulkhead_val);
    } else {
        config.bulkhead.files_max_concurrent = 50;
    }

    auto emg_slots = source.get("SECURECLOUD_GATEWAY_BULKHEAD_EMERGENCY_RESERVED");
    if (!emg_slots.has_value()) {
        emg_slots = source.get("SECURECLOUD_GATEWAY_BULKHEAD_EMERGENCY_MAX");
    }
    if (emg_slots.has_value()) {
        parse_uint32("SECURECLOUD_GATEWAY_BULKHEAD_EMERGENCY_RESERVED", emg_slots.value(),
                     config.bulkhead.emergency_reserved_slots, out_errors, k_min_bulkhead_val, k_max_bulkhead_val);
    } else {
        config.bulkhead.emergency_reserved_slots = 10;
    }
}

void load_rate_limiting_config(GatewayConfig& config, const common::configuration::ConfigurationSource& source,
                               common::configuration::ValidationResult& out_errors) {
    auto enabled_str = source.get("SECURECLOUD_GATEWAY_RATE_LIMIT_ENABLED");
    if (enabled_str.has_value()) {
        std::string val = enabled_str.value();
        for (auto& c : val) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        if (val == "true" || val == "1" || val == "yes" || val == "on") {
            config.rate_limiting.enabled = true;
        } else if (val == "false" || val == "0" || val == "no" || val == "off") {
            config.rate_limiting.enabled = false;
        } else {
            out_errors.add_error("SECURECLOUD_GATEWAY_RATE_LIMIT_ENABLED",
                                 "Invalid boolean value: " + enabled_str.value());
        }
    } else {
        config.rate_limiting.enabled = true;
    }

    auto refill_str = source.get("SECURECLOUD_GATEWAY_RATE_LIMIT_REFILL_RATE");
    if (refill_str.has_value()) {
        try {
            size_t pos = 0;
            double v = std::stod(refill_str.value(), &pos);
            if (pos != refill_str.value().size() || std::isnan(v) || std::isinf(v) || v < 0.1 || v > 100000.0) {
                out_errors.add_error("SECURECLOUD_GATEWAY_RATE_LIMIT_REFILL_RATE",
                                     "Value out of bounds [0.1, 100000.0]: " + refill_str.value());
            } else {
                config.rate_limiting.refill_rate_per_sec = v;
            }
        } catch (...) {
            out_errors.add_error("SECURECLOUD_GATEWAY_RATE_LIMIT_REFILL_RATE",
                                 "Invalid double value: " + refill_str.value());
        }
    } else {
        config.rate_limiting.refill_rate_per_sec = 50.0;
    }

    auto burst_str = source.get("SECURECLOUD_GATEWAY_RATE_LIMIT_BURST");
    if (burst_str.has_value()) {
        parse_uint32("SECURECLOUD_GATEWAY_RATE_LIMIT_BURST", burst_str.value(), config.rate_limiting.burst_capacity,
                     out_errors, 1, 100000);
    } else {
        config.rate_limiting.burst_capacity = 100;
    }

    auto max_clients_str = source.get("SECURECLOUD_GATEWAY_RATE_LIMIT_MAX_CLIENTS");
    if (max_clients_str.has_value()) {
        uint32_t val = 10000;
        parse_uint32("SECURECLOUD_GATEWAY_RATE_LIMIT_MAX_CLIENTS", max_clients_str.value(), val, out_errors, 10,
                     500000);
        config.rate_limiting.max_tracked_clients = val;
    } else {
        config.rate_limiting.max_tracked_clients = 10000;
    }

    auto ttl_str = source.get("SECURECLOUD_GATEWAY_RATE_LIMIT_CLIENT_TTL_SEC");
    if (ttl_str.has_value()) {
        uint32_t val = 300;
        parse_uint32("SECURECLOUD_GATEWAY_RATE_LIMIT_CLIENT_TTL_SEC", ttl_str.value(), val, out_errors, 1, 86400);
        config.rate_limiting.client_ttl = std::chrono::seconds(val);
    } else {
        config.rate_limiting.client_ttl = std::chrono::seconds(300);
    }
}

void load_circuit_breaker_config(GatewayConfig& config, const common::configuration::ConfigurationSource& source,
                                 common::configuration::ValidationResult& out_errors) {
    auto enabled_str = source.get("SECURECLOUD_GATEWAY_CIRCUIT_BREAKER_ENABLED");
    if (enabled_str.has_value()) {
        if (enabled_str.value() == "true" || enabled_str.value() == "1") {
            config.circuit_breaker.enabled = true;
        } else if (enabled_str.value() == "false" || enabled_str.value() == "0") {
            config.circuit_breaker.enabled = false;
        } else {
            out_errors.add_error("SECURECLOUD_GATEWAY_CIRCUIT_BREAKER_ENABLED",
                                 "Invalid boolean value: " + enabled_str.value());
        }
    } else {
        config.circuit_breaker.enabled = true;
    }

    auto threshold_str = source.get("SECURECLOUD_GATEWAY_CIRCUIT_BREAKER_FAILURE_THRESHOLD");
    if (threshold_str.has_value()) {
        parse_uint32("SECURECLOUD_GATEWAY_CIRCUIT_BREAKER_FAILURE_THRESHOLD", threshold_str.value(),
                     config.circuit_breaker.failure_threshold, out_errors, 1, 100);
    } else {
        config.circuit_breaker.failure_threshold = 5;
    }

    auto timeout_str = source.get("SECURECLOUD_GATEWAY_CIRCUIT_BREAKER_RECOVERY_TIMEOUT_MS");
    if (timeout_str.has_value()) {
        parse_uint32("SECURECLOUD_GATEWAY_CIRCUIT_BREAKER_RECOVERY_TIMEOUT_MS", timeout_str.value(),
                     config.circuit_breaker.recovery_timeout_ms, out_errors, 100, 300000);
    } else {
        config.circuit_breaker.recovery_timeout_ms = 5000;
    }

    auto probes_str = source.get("SECURECLOUD_GATEWAY_CIRCUIT_BREAKER_HALF_OPEN_PROBES");
    if (probes_str.has_value()) {
        parse_uint32("SECURECLOUD_GATEWAY_CIRCUIT_BREAKER_HALF_OPEN_PROBES", probes_str.value(),
                     config.circuit_breaker.half_open_probe_count, out_errors, 1, 10);
    } else {
        config.circuit_breaker.half_open_probe_count = 1;
    }
}

void load_streaming_config(GatewayConfig& config, const common::configuration::ConfigurationSource& source,
                           common::configuration::ValidationResult& out_errors) {
    auto chunk_str = source.get("SECURECLOUD_GATEWAY_STREAM_MAX_CHUNK_BYTES");
    if (!chunk_str.has_value()) {
        chunk_str = source.get("SECURECLOUD_GW_STREAM_MAX_CHUNK_BYTES");
    }
    if (chunk_str.has_value()) {
        parse_size_t("SECURECLOUD_GATEWAY_STREAM_MAX_CHUNK_BYTES", chunk_str.value(),
                     config.streaming.max_chunk_size_bytes, out_errors, 65536, 67108864);
    } else {
        config.streaming.max_chunk_size_bytes = 4194304;
    }

    auto buf_str = source.get("SECURECLOUD_GATEWAY_STREAM_MAX_BUFFER_BYTES");
    if (!buf_str.has_value()) {
        buf_str = source.get("SECURECLOUD_GW_STREAM_MAX_BUFFER_BYTES");
    }
    if (buf_str.has_value()) {
        parse_size_t("SECURECLOUD_GATEWAY_STREAM_MAX_BUFFER_BYTES", buf_str.value(),
                     config.streaming.max_stream_buffer_bytes, out_errors, 65536, 268435456);
    } else {
        config.streaming.max_stream_buffer_bytes = 8388608;
    }

    auto idle_str = source.get("SECURECLOUD_GATEWAY_STREAM_IDLE_TIMEOUT_MS");
    if (!idle_str.has_value()) {
        idle_str = source.get("SECURECLOUD_GW_STREAM_IDLE_TIMEOUT_MS");
    }
    if (idle_str.has_value()) {
        parse_uint32("SECURECLOUD_GATEWAY_STREAM_IDLE_TIMEOUT_MS", idle_str.value(), config.streaming.idle_timeout_ms,
                     out_errors, 1000, 300000);
    } else {
        config.streaming.idle_timeout_ms = 30000;
    }

    if (config.streaming.max_stream_buffer_bytes < config.streaming.max_chunk_size_bytes) {
        out_errors.add_error("SECURECLOUD_GATEWAY_STREAM_MAX_BUFFER_BYTES",
                             "max_stream_buffer_bytes must be greater than or equal to max_chunk_size_bytes");
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

std::string GatewayConfig::https_listen_endpoint() const {
    return http_listen_address + ":" + std::to_string(tls.https_listen_port);
}

void GatewayConfig::validate_tls_paths(common::configuration::ValidationResult& out_errors) const {
    if (!tls.enabled) {
        return;
    }
    if (tls.cert_path.empty()) {
        out_errors.add_error("SECURECLOUD_GATEWAY_TLS_CERT_PATH", "TLS certificate path cannot be empty");
    } else if (!std::filesystem::exists(std::filesystem::path(tls.cert_path))) {
        out_errors.add_error("SECURECLOUD_GATEWAY_TLS_CERT_PATH",
                             "certificate file does not exist on disk: '" + tls.cert_path + "'");
    }

    if (tls.key_path.empty()) {
        out_errors.add_error("SECURECLOUD_GATEWAY_TLS_KEY_PATH", "TLS key path cannot be empty");
    } else if (!std::filesystem::exists(std::filesystem::path(tls.key_path))) {
        out_errors.add_error("SECURECLOUD_GATEWAY_TLS_KEY_PATH",
                             "private key file does not exist on disk: '" + tls.key_path + "'");
    }

    if (!tls.ca_chain_path.empty() && !std::filesystem::exists(std::filesystem::path(tls.ca_chain_path))) {
        out_errors.add_error("SECURECLOUD_GATEWAY_TLS_CA_PATH",
                             "CA chain file does not exist on disk: '" + tls.ca_chain_path + "'");
    }
}

GatewayConfig GatewayConfig::load(const common::configuration::ConfigurationSource& source,
                                  common::configuration::ValidationResult& out_errors, bool validate_file_paths) {
    GatewayConfig config;
    config.common = common::configuration::CommonServiceConfig::load(source, "gateway", "Gateway Service",
                                                                     k_default_gateway_grpc_port, out_errors);

    load_http_config(config, source, out_errors);
    load_tls_config(config, source, out_errors, validate_file_paths);
    load_limits_config(config, source, out_errors);
    load_deadlines_config(config, source, out_errors);
    load_bulkhead_config(config, source, out_errors);
    load_rate_limiting_config(config, source, out_errors);
    load_circuit_breaker_config(config, source, out_errors);
    load_streaming_config(config, source, out_errors);
    load_downstream_endpoints(config, source, out_errors);

    config.peer_probe_target = source.get("SECURECLOUD_GATEWAY_PEER_PROBE_TARGET")
                                   .value_or(source.get("SECURECLOUD_PEER_PROBE_TARGET").value_or(""));

    config.peer_probe_name = source.get("SECURECLOUD_GATEWAY_PEER_PROBE_NAME")
                                 .value_or(source.get("SECURECLOUD_PEER_PROBE_NAME").value_or(""));

    return config;
}

} // namespace securecloud::gateway
