#include "auth_config.hpp"

#include "auth/db/postgres_connection_pool.hpp"
#include "securecloud/configuration/config_parser.hpp"

#include <charconv>
#include <optional>
#include <string_view>

namespace securecloud::auth {

namespace {

constexpr uint16_t k_default_auth_port = 50052;
constexpr uint16_t k_default_postgres_port = 5432;

std::optional<uint64_t> parse_u64_bounded(std::string_view key,
                                          std::string_view raw,
                                          uint64_t min_val,
                                          uint64_t max_val,
                                          common::configuration::ValidationResult& out_errors) {
    uint64_t parsed = 0;
    const auto* begin = raw.data();
    const auto* end = raw.data() + raw.size();
    const auto [ptr, ec] = std::from_chars(begin, end, parsed);
    if (ec != std::errc{} || ptr != end) {
        out_errors.add_error(std::string(key), "must be a valid unsigned integer");
        return std::nullopt;
    }
    if (parsed < min_val || parsed > max_val) {
        out_errors.add_error(std::string(key),
                             "must be between " + std::to_string(min_val) + " and " + std::to_string(max_val));
        return std::nullopt;
    }
    return parsed;
}

std::optional<bool> parse_bool_flag(std::string_view key,
                                    std::string_view raw,
                                    common::configuration::ValidationResult& out_errors) {
    if (raw == "true" || raw == "TRUE" || raw == "1" || raw == "yes" || raw == "YES") {
        return true;
    }
    if (raw == "false" || raw == "FALSE" || raw == "0" || raw == "no" || raw == "NO") {
        return false;
    }
    out_errors.add_error(std::string(key), "must be a boolean (true/false/1/0)");
    return std::nullopt;
}

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

    auto instance_val = source.get("SECURECLOUD_AUTH_INSTANCE_ID");
    if (instance_val.has_value() && !instance_val.value().empty()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_AUTH_INSTANCE_ID",
                                                                        instance_val.value(), out_errors, false);
        if (parsed.has_value()) {
            config.producer_instance = parsed.value();
        }
    } else {
        auto hostname_val = source.get("HOSTNAME");
        if (hostname_val.has_value() && !hostname_val.value().empty()) {
            config.producer_instance = hostname_val.value();
        }
    }

    // --- Audit gRPC client & Outbox relay settings ---
    if (auto relay_enabled = source.get("SECURECLOUD_AUTH_OUTBOX_RELAY_ENABLED");
        relay_enabled.has_value() && !relay_enabled->empty()) {
        if (auto parsed = parse_bool_flag("SECURECLOUD_AUTH_OUTBOX_RELAY_ENABLED", *relay_enabled, out_errors)) {
            config.outbox_relay_enabled = *parsed;
        }
    }

    auto audit_ep = source.get("SECURECLOUD_AUTH_AUDIT_ENDPOINT");
    if (!audit_ep.has_value() || audit_ep->empty()) {
        audit_ep = source.get("SECURECLOUD_AUDIT_ENDPOINT");
    }
    if (audit_ep.has_value() && !audit_ep->empty()) {
        auto parsed =
            common::configuration::ConfigParser::parse_string("SECURECLOUD_AUTH_AUDIT_ENDPOINT", *audit_ep, out_errors, false);
        if (parsed.has_value()) {
            config.audit_endpoint = *parsed;
        }
    }

    if (auto audit_timeout = source.get("SECURECLOUD_AUTH_AUDIT_TIMEOUT_MS");
        audit_timeout.has_value() && !audit_timeout->empty()) {
        if (auto parsed = parse_u64_bounded("SECURECLOUD_AUTH_AUDIT_TIMEOUT_MS", *audit_timeout, 50, 60000, out_errors)) {
            config.audit_timeout = std::chrono::milliseconds(static_cast<int64_t>(*parsed));
        }
    }

    if (auto peer_san = source.get("SECURECLOUD_AUTH_AUDIT_PEER_SAN");
        peer_san.has_value() && !peer_san->empty()) {
        auto parsed =
            common::configuration::ConfigParser::parse_string("SECURECLOUD_AUTH_AUDIT_PEER_SAN", *peer_san, out_errors, false);
        if (parsed.has_value()) {
            config.audit_expected_peer_san = *parsed;
        }
    }

    if (auto poll_ms = source.get("SECURECLOUD_AUTH_OUTBOX_POLL_INTERVAL_MS");
        poll_ms.has_value() && !poll_ms->empty()) {
        if (auto parsed = parse_u64_bounded("SECURECLOUD_AUTH_OUTBOX_POLL_INTERVAL_MS", *poll_ms, 10, 60000, out_errors)) {
            config.outbox_relay.poll_interval = std::chrono::milliseconds(static_cast<int64_t>(*parsed));
        }
    }

    if (auto batch_sz = source.get("SECURECLOUD_AUTH_OUTBOX_BATCH_SIZE");
        batch_sz.has_value() && !batch_sz->empty()) {
        if (auto parsed = parse_u64_bounded("SECURECLOUD_AUTH_OUTBOX_BATCH_SIZE", *batch_sz, 1, 100, out_errors)) {
            config.outbox_relay.batch_size = static_cast<size_t>(*parsed);
        }
    }

    if (auto lease_sec = source.get("SECURECLOUD_AUTH_OUTBOX_LEASE_SECONDS");
        lease_sec.has_value() && !lease_sec->empty()) {
        if (auto parsed = parse_u64_bounded("SECURECLOUD_AUTH_OUTBOX_LEASE_SECONDS", *lease_sec, 1, 3600, out_errors)) {
            config.outbox_relay.lease_duration = std::chrono::seconds(static_cast<int64_t>(*parsed));
        }
    }

    if (auto init_bo = source.get("SECURECLOUD_AUTH_OUTBOX_INITIAL_BACKOFF_MS");
        init_bo.has_value() && !init_bo->empty()) {
        if (auto parsed =
                parse_u64_bounded("SECURECLOUD_AUTH_OUTBOX_INITIAL_BACKOFF_MS", *init_bo, 10, 60000, out_errors)) {
            config.outbox_relay.initial_backoff = std::chrono::milliseconds(static_cast<int64_t>(*parsed));
        }
    }

    if (auto max_bo = source.get("SECURECLOUD_AUTH_OUTBOX_MAX_BACKOFF_MS");
        max_bo.has_value() && !max_bo->empty()) {
        if (auto parsed =
                parse_u64_bounded("SECURECLOUD_AUTH_OUTBOX_MAX_BACKOFF_MS", *max_bo, 50, 300000, out_errors)) {
            config.outbox_relay.max_backoff = std::chrono::milliseconds(static_cast<int64_t>(*parsed));
        }
    }

    if (auto ret_hours = source.get("SECURECLOUD_AUTH_OUTBOX_RETENTION_HOURS");
        ret_hours.has_value() && !ret_hours->empty()) {
        if (auto parsed =
                parse_u64_bounded("SECURECLOUD_AUTH_OUTBOX_RETENTION_HOURS", *ret_hours, 1, 24 * 365, out_errors)) {
            config.outbox_relay.published_retention = std::chrono::hours(static_cast<int64_t>(*parsed));
        }
    }

    if (auto purge_sz = source.get("SECURECLOUD_AUTH_OUTBOX_PURGE_BATCH_SIZE");
        purge_sz.has_value() && !purge_sz->empty()) {
        if (auto parsed =
                parse_u64_bounded("SECURECLOUD_AUTH_OUTBOX_PURGE_BATCH_SIZE", *purge_sz, 1, 10000, out_errors)) {
            config.outbox_relay.purge_batch_size = static_cast<size_t>(*parsed);
        }
    }

    return config;
}

std::shared_ptr<db::PostgresConnectionPool> AuthConfig::create_database_pool() const {
    return std::make_shared<db::PostgresConnectionPool>(*this);
}

} // namespace securecloud::auth
