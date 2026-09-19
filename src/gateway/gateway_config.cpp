#include "gateway_config.hpp"

#include "securecloud/configuration/config_parser.hpp"

namespace securecloud::gateway {

namespace {

constexpr uint16_t k_default_gateway_port = 50051;

} // namespace

GatewayConfig GatewayConfig::load(const common::configuration::ConfigurationSource& source,
                                  common::configuration::ValidationResult& out_errors) {
    GatewayConfig config;
    config.common = common::configuration::CommonServiceConfig::load(source, "gateway", "Gateway Service",
                                                                     k_default_gateway_port, out_errors);

    auto auth_ep = source.get("SECURECLOUD_GATEWAY_AUTH_ENDPOINT");
    if (auth_ep.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_GATEWAY_AUTH_ENDPOINT",
                                                                        auth_ep.value(), out_errors, false);
        if (parsed.has_value()) {
            config.auth_endpoint = parsed.value();
        }
    }

    auto msg_ep = source.get("SECURECLOUD_GATEWAY_MESSAGING_ENDPOINT");
    if (msg_ep.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_GATEWAY_MESSAGING_ENDPOINT",
                                                                        msg_ep.value(), out_errors, false);
        if (parsed.has_value()) {
            config.messaging_endpoint = parsed.value();
        }
    }

    auto files_ep = source.get("SECURECLOUD_GATEWAY_FILES_ENDPOINT");
    if (files_ep.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_GATEWAY_FILES_ENDPOINT",
                                                                        files_ep.value(), out_errors, false);
        if (parsed.has_value()) {
            config.files_endpoint = parsed.value();
        }
    }

    auto audit_ep = source.get("SECURECLOUD_GATEWAY_AUDIT_ENDPOINT");
    if (audit_ep.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_GATEWAY_AUDIT_ENDPOINT",
                                                                        audit_ep.value(), out_errors, false);
        if (parsed.has_value()) {
            config.audit_endpoint = parsed.value();
        }
    }

    // Peer probe resolution (canonical service prefix > legacy fallback)
    config.peer_probe_target = source.get("SECURECLOUD_GATEWAY_PEER_PROBE_TARGET")
                                   .value_or(source.get("SECURECLOUD_PEER_PROBE_TARGET").value_or(""));

    config.peer_probe_name = source.get("SECURECLOUD_GATEWAY_PEER_PROBE_NAME")
                                 .value_or(source.get("SECURECLOUD_PEER_PROBE_NAME").value_or(""));

    return config;
}

} // namespace securecloud::gateway
