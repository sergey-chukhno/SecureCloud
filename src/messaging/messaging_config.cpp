#include "messaging_config.hpp"

#include "securecloud/configuration/config_parser.hpp"

namespace securecloud::messaging {

namespace {

constexpr uint16_t k_default_messaging_port = 50053;
constexpr uint16_t k_default_scylla_port = 9042;

} // namespace

MessagingConfig MessagingConfig::load(const common::configuration::ConfigurationSource& source,
                                      common::configuration::ValidationResult& out_errors) {
    MessagingConfig config;
    config.common = common::configuration::CommonServiceConfig::load(source, "messaging", "Messaging Service",
                                                                     k_default_messaging_port, out_errors);

    auto host_val = source.get("SECURECLOUD_MESSAGING_SCYLLA_HOST");
    if (host_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_MESSAGING_SCYLLA_HOST",
                                                                        host_val.value(), out_errors, false);
        if (parsed.has_value()) {
            config.scylla_host = parsed.value();
        }
    }

    auto port_val = source.get("SECURECLOUD_MESSAGING_SCYLLA_PORT");
    if (port_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint16("SECURECLOUD_MESSAGING_SCYLLA_PORT",
                                                                        port_val.value(), out_errors);
        if (parsed.has_value()) {
            config.scylla_port = parsed.value();
        }
    } else {
        config.scylla_port = k_default_scylla_port;
    }

    auto keyspace_val = source.get("SECURECLOUD_MESSAGING_SCYLLA_KEYSPACE");
    if (keyspace_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_MESSAGING_SCYLLA_KEYSPACE",
                                                                        keyspace_val.value(), out_errors, false);
        if (parsed.has_value()) {
            config.scylla_keyspace = parsed.value();
        }
    }

    return config;
}

} // namespace securecloud::messaging
