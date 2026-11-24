#include "files_config.hpp"

#include "securecloud/configuration/config_parser.hpp"

namespace securecloud::files {

namespace {

constexpr uint16_t k_default_files_port = 50054;
constexpr uint16_t k_default_postgres_port = 5432;
constexpr size_t k_max_relay_batch_size = 100;

std::optional<bool> parse_bool_strict(std::string_view key, std::string_view raw,
                                      common::configuration::ValidationResult& out_errors) {
    if (raw == "true" || raw == "1" || raw == "TRUE" || raw == "yes" || raw == "YES") {
        return true;
    }
    if (raw == "false" || raw == "0" || raw == "FALSE" || raw == "no" || raw == "NO") {
        return false;
    }
    out_errors.add_error(std::string(key), "invalid boolean value");
    return std::nullopt;
}

std::optional<int64_t> parse_int64_strict(std::string_view key, std::string_view raw, int64_t min_val, int64_t max_val,
                                          common::configuration::ValidationResult& out_errors) {
    int64_t val = 0;
    const auto* end = raw.data() + raw.size();
    auto [ptr, ec] = std::from_chars(raw.data(), end, val);
    if (ec != std::errc{} || ptr != end) {
        out_errors.add_error(std::string(key), "invalid integer value");
        return std::nullopt;
    }
    if (val < min_val || val > max_val) {
        out_errors.add_error(std::string(key), "value out of allowed bounds [" + std::to_string(min_val) + ", " +
                                                   std::to_string(max_val) + "]");
        return std::nullopt;
    }
    return val;
}

std::optional<double> parse_double_strict(std::string_view key, std::string_view raw, double min_val, double max_val,
                                          common::configuration::ValidationResult& out_errors) {
    try {
        size_t idx = 0;
        std::string str(raw);
        double val = std::stod(str, &idx);
        if (idx != str.size() || !std::isfinite(val)) {
            out_errors.add_error(std::string(key), "invalid floating-point value");
            return std::nullopt;
        }
        if (val < min_val || val > max_val) {
            out_errors.add_error(std::string(key), "value out of allowed bounds");
            return std::nullopt;
        }
        return val;
    } catch (...) {
        out_errors.add_error(std::string(key), "invalid floating-point value");
        return std::nullopt;
    }
}

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

void load_audit_outbox_config(FilesConfig& config, const common::configuration::ConfigurationSource& source,
                              common::configuration::ValidationResult& out_errors) {
    auto enabled_val = source.get("SECURECLOUD_FILES_AUDIT_RELAY_ENABLED");
    if (enabled_val.has_value()) {
        auto parsed = parse_bool_strict("SECURECLOUD_FILES_AUDIT_RELAY_ENABLED", enabled_val.value(), out_errors);
        if (parsed.has_value()) {
            config.audit.outbox_relay_enabled = parsed.value();
        }
    }

    auto ep_val = source.get("SECURECLOUD_FILES_AUDIT_ENDPOINT");
    std::string_view ep_key = "SECURECLOUD_FILES_AUDIT_ENDPOINT";
    if (!ep_val.has_value()) {
        ep_val = source.get("SECURECLOUD_AUDIT_ENDPOINT");
        ep_key = "SECURECLOUD_AUDIT_ENDPOINT";
    }
    if (ep_val.has_value()) {
        auto parsed =
            common::configuration::ConfigParser::parse_string(std::string(ep_key), ep_val.value(), out_errors, false);
        if (parsed.has_value()) {
            config.audit.audit_endpoint = parsed.value();
        }
    }
    if (config.audit.audit_endpoint.empty()) {
        out_errors.add_error(std::string(ep_key), "audit endpoint must not be empty");
    }

    auto timeout_val = source.get("SECURECLOUD_FILES_AUDIT_TIMEOUT_MS");
    if (timeout_val.has_value()) {
        auto parsed =
            parse_int64_strict("SECURECLOUD_FILES_AUDIT_TIMEOUT_MS", timeout_val.value(), 50, 60000, out_errors);
        if (parsed.has_value()) {
            config.audit.audit_timeout = std::chrono::milliseconds(parsed.value());
        }
    }

    auto san_val = source.get("SECURECLOUD_FILES_AUDIT_PEER_SAN");
    std::string_view san_key = "SECURECLOUD_FILES_AUDIT_PEER_SAN";
    if (!san_val.has_value()) {
        san_val = source.get("SECURECLOUD_AUDIT_EXPECTED_SAN");
        san_key = "SECURECLOUD_AUDIT_EXPECTED_SAN";
    }
    if (san_val.has_value()) {
        auto parsed =
            common::configuration::ConfigParser::parse_string(std::string(san_key), san_val.value(), out_errors, false);
        if (parsed.has_value()) {
            config.audit.audit_expected_peer_san = parsed.value();
        }
    }
    if (config.audit.audit_expected_peer_san.empty()) {
        out_errors.add_error(std::string(san_key), "expected peer SAN must not be empty");
    }

    auto inst_val = source.get("SECURECLOUD_SERVICE_INSTANCE");
    std::string_view inst_key = "SECURECLOUD_SERVICE_INSTANCE";
    if (!inst_val.has_value()) {
        inst_val = source.get("HOSTNAME");
        inst_key = "HOSTNAME";
    }
    if (inst_val.has_value() && !inst_val.value().empty()) {
        auto parsed = common::configuration::ConfigParser::parse_string(std::string(inst_key), inst_val.value(),
                                                                        out_errors, false);
        if (parsed.has_value()) {
            config.audit.producer_instance = parsed.value();
        }
    }
    if (config.audit.producer_instance.empty()) {
        out_errors.add_error(std::string(inst_key), "producer instance must not be empty");
    }

    auto& relay = config.audit.relay;

    if (auto v = source.get("SECURECLOUD_FILES_AUDIT_POLL_INTERVAL_MS"); v.has_value()) {
        if (auto p = parse_int64_strict("SECURECLOUD_FILES_AUDIT_POLL_INTERVAL_MS", v.value(), 10, 60000, out_errors)) {
            relay.poll_interval = std::chrono::milliseconds(*p);
        }
    }

    if (auto v = source.get("SECURECLOUD_FILES_AUDIT_BATCH_SIZE"); v.has_value()) {
        if (auto p = parse_int64_strict("SECURECLOUD_FILES_AUDIT_BATCH_SIZE", v.value(), 1, 1000, out_errors)) {
            relay.batch_size = std::min<size_t>(static_cast<size_t>(*p), k_max_relay_batch_size);
        }
    }

    if (auto v = source.get("SECURECLOUD_FILES_AUDIT_LEASE_DURATION_SEC"); v.has_value()) {
        if (auto p = parse_int64_strict("SECURECLOUD_FILES_AUDIT_LEASE_DURATION_SEC", v.value(), 1, 3600, out_errors)) {
            relay.lease_duration = std::chrono::seconds(*p);
        }
    }

    if (auto v = source.get("SECURECLOUD_FILES_AUDIT_INITIAL_BACKOFF_MS"); v.has_value()) {
        if (auto p =
                parse_int64_strict("SECURECLOUD_FILES_AUDIT_INITIAL_BACKOFF_MS", v.value(), 10, 60000, out_errors)) {
            relay.initial_backoff = std::chrono::milliseconds(*p);
        }
    }

    if (auto v = source.get("SECURECLOUD_FILES_AUDIT_MAX_BACKOFF_MS"); v.has_value()) {
        if (auto p = parse_int64_strict("SECURECLOUD_FILES_AUDIT_MAX_BACKOFF_MS", v.value(), 50, 300000, out_errors)) {
            relay.max_backoff = std::chrono::milliseconds(*p);
        }
    }

    if (relay.max_backoff < relay.initial_backoff) {
        out_errors.add_error("SECURECLOUD_FILES_AUDIT_MAX_BACKOFF_MS",
                             "max_backoff must be greater than or equal to initial_backoff");
    }

    if (auto v = source.get("SECURECLOUD_FILES_AUDIT_BACKOFF_MULTIPLIER"); v.has_value()) {
        if (auto p =
                parse_double_strict("SECURECLOUD_FILES_AUDIT_BACKOFF_MULTIPLIER", v.value(), 1.0, 10.0, out_errors)) {
            relay.backoff_multiplier = *p;
        }
    }

    if (auto v = source.get("SECURECLOUD_FILES_AUDIT_JITTER_RATIO"); v.has_value()) {
        if (auto p = parse_double_strict("SECURECLOUD_FILES_AUDIT_JITTER_RATIO", v.value(), 0.0, 1.0, out_errors)) {
            relay.jitter_ratio = *p;
        }
    }

    if (auto v = source.get("SECURECLOUD_FILES_AUDIT_MAX_RETRIES"); v.has_value()) {
        if (auto p = parse_int64_strict("SECURECLOUD_FILES_AUDIT_MAX_RETRIES", v.value(), 1, 100, out_errors)) {
            relay.max_retries = static_cast<uint32_t>(*p);
        }
    }

    if (auto v = source.get("SECURECLOUD_FILES_AUDIT_RETENTION_HOURS"); v.has_value()) {
        if (auto p =
                parse_int64_strict("SECURECLOUD_FILES_AUDIT_RETENTION_HOURS", v.value(), 1, 24 * 365, out_errors)) {
            relay.published_retention = std::chrono::hours(*p);
        }
    }

    if (auto v = source.get("SECURECLOUD_FILES_AUDIT_PURGE_INTERVAL_SEC"); v.has_value()) {
        if (auto p =
                parse_int64_strict("SECURECLOUD_FILES_AUDIT_PURGE_INTERVAL_SEC", v.value(), 1, 86400, out_errors)) {
            relay.purge_interval = std::chrono::seconds(*p);
        }
    }

    if (auto v = source.get("SECURECLOUD_FILES_AUDIT_PURGE_BATCH_SIZE"); v.has_value()) {
        if (auto p = parse_int64_strict("SECURECLOUD_FILES_AUDIT_PURGE_BATCH_SIZE", v.value(), 1, 50000, out_errors)) {
            relay.purge_batch_size = static_cast<size_t>(*p);
        }
    }

    if (auto v = source.get("SECURECLOUD_FILES_AUDIT_SHUTDOWN_DRAIN_MS"); v.has_value()) {
        if (auto p = parse_int64_strict("SECURECLOUD_FILES_AUDIT_SHUTDOWN_DRAIN_MS", v.value(), 0, 60000, out_errors)) {
            relay.shutdown_drain_timeout = std::chrono::milliseconds(*p);
        }
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
    load_audit_outbox_config(config, source, out_errors);
    config.resources = FilesResourceConfig::load(source, out_errors);

    return config;
}

} // namespace securecloud::files
