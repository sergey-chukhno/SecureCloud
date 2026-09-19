#include "securecloud/configuration/common_service_config.hpp"

#include "securecloud/configuration/config_parser.hpp"

#include <algorithm>
#include <cctype>
#include <iostream>

namespace securecloud::common::configuration {

namespace {

constexpr uint64_t k_min_shutdown_timeout_ms = 100;
constexpr uint64_t k_max_shutdown_timeout_ms = 300000;
constexpr std::chrono::milliseconds k_default_shutdown_timeout{5000};

constexpr std::string_view k_default_ca_path = "/etc/securecloud/certs/ca.crt";
constexpr std::string_view k_default_cert_path = "/etc/securecloud/certs/service.crt";
constexpr std::string_view k_default_key_path = "/etc/securecloud/certs/service.key";

std::string to_upper(std::string_view str) {
    std::string upper(str);
    std::ranges::transform(upper, upper.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return upper;
}

uint16_t resolve_grpc_port(const ConfigurationSource& source, std::string_view service_name,
                           const std::string& upper_service, uint16_t default_port, ValidationResult& out_errors) {
    std::string service_port_var = "SECURECLOUD_" + upper_service + "_GRPC_PORT";
    auto opt_service_port = source.get(service_port_var);
    if (opt_service_port.has_value()) {
        auto parsed_port = ConfigParser::parse_uint16(service_port_var, opt_service_port.value(), out_errors);
        return parsed_port.value_or(default_port);
    }

    auto opt_legacy_port = source.get("SECURECLOUD_GRPC_PORT");
    if (opt_legacy_port.has_value()) {
        std::clog << "[SecureCloud] [" << service_name
                  << "] NOTICE: Using transitional variable 'SECURECLOUD_GRPC_PORT'. "
                  << "Scheduled for deprecation in M2 in favor of '" << service_port_var << "'.\n";
        auto parsed_port = ConfigParser::parse_uint16("SECURECLOUD_GRPC_PORT", opt_legacy_port.value(), out_errors);
        return parsed_port.value_or(default_port);
    }

    return default_port;
}

std::string resolve_grpc_host(const ConfigurationSource& source, const std::string& upper_service,
                              ValidationResult& out_errors) {
    std::string service_host_var = "SECURECLOUD_" + upper_service + "_GRPC_HOST";
    auto opt_service_host = source.get(service_host_var);
    if (opt_service_host.has_value()) {
        auto parsed_host = ConfigParser::parse_string(service_host_var, opt_service_host.value(), out_errors, false);
        return parsed_host.value_or("0.0.0.0");
    }

    auto opt_global_host = source.get("SECURECLOUD_GRPC_HOST");
    if (opt_global_host.has_value()) {
        auto parsed_host =
            ConfigParser::parse_string("SECURECLOUD_GRPC_HOST", opt_global_host.value(), out_errors, false);
        return parsed_host.value_or("0.0.0.0");
    }

    return "0.0.0.0";
}

security::SecurityCredentialsConfig resolve_tls_credentials(const ConfigurationSource& source,
                                                            ValidationResult& out_errors) {
    security::SecurityCredentialsConfig creds;

    auto ca_str = source.get("SECURECLOUD_CA_CERT_PATH").value_or(std::string(k_default_ca_path));
    auto parsed_ca = ConfigParser::parse_path("SECURECLOUD_CA_CERT_PATH", ca_str, out_errors, false);
    if (parsed_ca.has_value()) {
        creds.ca_cert_path = parsed_ca.value();
    }

    auto cert_str = source.get("SECURECLOUD_SERVICE_CERT_PATH").value_or(std::string(k_default_cert_path));
    auto parsed_cert = ConfigParser::parse_path("SECURECLOUD_SERVICE_CERT_PATH", cert_str, out_errors, false);
    if (parsed_cert.has_value()) {
        creds.service_cert_path = parsed_cert.value();
    }

    auto key_str = source.get("SECURECLOUD_SERVICE_KEY_PATH").value_or(std::string(k_default_key_path));
    auto parsed_key = ConfigParser::parse_path("SECURECLOUD_SERVICE_KEY_PATH", key_str, out_errors, false);
    if (parsed_key.has_value()) {
        creds.service_key_path = parsed_key.value();
    }

    return creds;
}

std::chrono::milliseconds resolve_shutdown_timeout(const ConfigurationSource& source, ValidationResult& out_errors) {
    auto opt_timeout = source.get("SECURECLOUD_SHUTDOWN_TIMEOUT_MS");
    if (opt_timeout.has_value()) {
        auto parsed_timeout =
            ConfigParser::parse_duration_ms("SECURECLOUD_SHUTDOWN_TIMEOUT_MS", opt_timeout.value(), out_errors,
                                            k_min_shutdown_timeout_ms, k_max_shutdown_timeout_ms);
        return parsed_timeout.value_or(k_default_shutdown_timeout);
    }

    return k_default_shutdown_timeout;
}

} // namespace

std::string CommonServiceConfig::listen_address() const {
    return grpc_host + ":" + std::to_string(grpc_port);
}

CommonServiceConfig CommonServiceConfig::load(const ConfigurationSource& source, std::string_view service_name,
                                              std::string_view service_display_name, uint16_t default_port,
                                              ValidationResult& out_errors) {
    CommonServiceConfig config;
    config.service_name = std::string(service_name);
    config.service_display_name = std::string(service_display_name);

    std::string upper_service = to_upper(service_name);

    config.grpc_port = resolve_grpc_port(source, service_name, upper_service, default_port, out_errors);
    config.grpc_host = resolve_grpc_host(source, upper_service, out_errors);
    config.tls_credentials = resolve_tls_credentials(source, out_errors);
    config.shutdown_timeout = resolve_shutdown_timeout(source, out_errors);

    return config;
}

} // namespace securecloud::common::configuration
