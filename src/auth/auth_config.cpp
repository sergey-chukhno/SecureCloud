#include "auth_config.hpp"

#include "securecloud/configuration/config_parser.hpp"

namespace securecloud::auth {

namespace {

constexpr uint16_t k_default_auth_port = 50052;
constexpr uint16_t k_default_postgres_port = 5432;

} // namespace

AuthConfig AuthConfig::load(const common::configuration::ConfigurationSource& source,
                            common::configuration::ValidationResult& out_errors) {
    AuthConfig config;
    config.common = common::configuration::CommonServiceConfig::load(source, "auth", "Auth Service",
                                                                     k_default_auth_port, out_errors);

    auto host_val = source.get("SECURECLOUD_AUTH_DB_HOST");
    if (host_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_AUTH_DB_HOST", host_val.value(),
                                                                        out_errors, false);
        if (parsed.has_value()) {
            config.db_host = parsed.value();
        }
    }

    auto port_val = source.get("SECURECLOUD_AUTH_DB_PORT");
    if (port_val.has_value()) {
        auto parsed =
            common::configuration::ConfigParser::parse_uint16("SECURECLOUD_AUTH_DB_PORT", port_val.value(), out_errors);
        if (parsed.has_value()) {
            config.db_port = parsed.value();
        }
    } else {
        config.db_port = k_default_postgres_port;
    }

    auto name_val = source.get("SECURECLOUD_AUTH_DB_NAME");
    if (name_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_AUTH_DB_NAME", name_val.value(),
                                                                        out_errors, false);
        if (parsed.has_value()) {
            config.db_name = parsed.value();
        }
    }

    auto user_val = source.get("SECURECLOUD_AUTH_DB_USER");
    if (user_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_AUTH_DB_USER", user_val.value(),
                                                                        out_errors, false);
        if (parsed.has_value()) {
            config.db_user = parsed.value();
        }
    }

    auto pass_val = source.get("SECURECLOUD_AUTH_DB_PASSWORD");
    if (!pass_val.has_value() || pass_val.value().empty()) {
        out_errors.add_error("SECURECLOUD_AUTH_DB_PASSWORD", "required configuration is missing or empty");
    } else {
        config.db_password = common::configuration::SecretString(pass_val.value());
    }

    return config;
}

} // namespace securecloud::auth
