#include "files_config.hpp"

#include "securecloud/configuration/config_parser.hpp"

namespace securecloud::files {

namespace {

constexpr uint16_t k_default_files_port = 50054;
constexpr uint16_t k_default_postgres_port = 5432;

void load_postgres_config(FilesConfig& config, const common::configuration::ConfigurationSource& source,
                          common::configuration::ValidationResult& out_errors) {
    auto host_val = source.get("SECURECLOUD_FILES_DB_HOST");
    if (host_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_FILES_DB_HOST", host_val.value(),
                                                                        out_errors, false);
        if (parsed.has_value()) {
            config.db_host = parsed.value();
        }
    }

    auto port_val = source.get("SECURECLOUD_FILES_DB_PORT");
    if (port_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint16("SECURECLOUD_FILES_DB_PORT", port_val.value(),
                                                                        out_errors);
        if (parsed.has_value()) {
            config.db_port = parsed.value();
        }
    } else {
        config.db_port = k_default_postgres_port;
    }

    auto name_val = source.get("SECURECLOUD_FILES_DB_NAME");
    if (name_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_FILES_DB_NAME", name_val.value(),
                                                                        out_errors, false);
        if (parsed.has_value()) {
            config.db_name = parsed.value();
        }
    }

    auto user_val = source.get("SECURECLOUD_FILES_DB_USER");
    if (user_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_FILES_DB_USER", user_val.value(),
                                                                        out_errors, false);
        if (parsed.has_value()) {
            config.db_user = parsed.value();
        }
    }

    auto pass_val = source.get("SECURECLOUD_FILES_DB_PASSWORD");
    if (!pass_val.has_value() || pass_val.value().empty()) {
        out_errors.add_error("SECURECLOUD_FILES_DB_PASSWORD", "required configuration is missing or empty");
    } else {
        config.db_password = common::configuration::SecretString(pass_val.value());
    }
}

void load_s3_config(FilesConfig& config, const common::configuration::ConfigurationSource& source,
                    common::configuration::ValidationResult& out_errors) {
    auto s3_ep = source.get("SECURECLOUD_FILES_S3_ENDPOINT");
    if (s3_ep.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_FILES_S3_ENDPOINT", s3_ep.value(),
                                                                        out_errors, false);
        if (parsed.has_value()) {
            config.s3_endpoint = parsed.value();
        }
    }

    auto s3_bkt = source.get("SECURECLOUD_FILES_S3_BUCKET");
    if (s3_bkt.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_FILES_S3_BUCKET", s3_bkt.value(),
                                                                        out_errors, false);
        if (parsed.has_value()) {
            config.s3_bucket = parsed.value();
        }
    }

    auto s3_key = source.get("SECURECLOUD_FILES_S3_ACCESS_KEY");
    if (s3_key.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_FILES_S3_ACCESS_KEY",
                                                                        s3_key.value(), out_errors, false);
        if (parsed.has_value()) {
            config.s3_access_key = parsed.value();
        }
    }

    auto s3_sec = source.get("SECURECLOUD_FILES_S3_SECRET_KEY");
    if (!s3_sec.has_value() || s3_sec.value().empty()) {
        out_errors.add_error("SECURECLOUD_FILES_S3_SECRET_KEY", "required configuration is missing or empty");
    } else {
        config.s3_secret_key = common::configuration::SecretString(s3_sec.value());
    }
}

} // namespace

FilesConfig FilesConfig::load(const common::configuration::ConfigurationSource& source,
                              common::configuration::ValidationResult& out_errors) {
    FilesConfig config;
    config.common = common::configuration::CommonServiceConfig::load(source, "files", "Files Service",
                                                                     k_default_files_port, out_errors);

    load_postgres_config(config, source, out_errors);
    load_s3_config(config, source, out_errors);

    return config;
}

} // namespace securecloud::files
