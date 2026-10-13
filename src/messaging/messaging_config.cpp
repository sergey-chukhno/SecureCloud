#include "messaging_config.hpp"

#include "securecloud/configuration/config_parser.hpp"

#include <string_view>

namespace securecloud::messaging {

namespace {

constexpr uint16_t k_default_messaging_port = 50053;
constexpr uint16_t k_default_scylla_port = 9042;

constexpr uint32_t k_min_connect_timeout_ms = 100;
constexpr uint32_t k_max_connect_timeout_ms = 60000;

constexpr uint32_t k_min_request_timeout_ms = 100;
constexpr uint32_t k_max_request_timeout_ms = 30000;

constexpr uint32_t k_min_connection_pool_size = 1;
constexpr uint32_t k_max_connection_pool_size = 128;

constexpr uint32_t k_min_submission_workers = 1;
constexpr uint32_t k_max_submission_workers = 128;

constexpr uint32_t k_min_delivery_workers = 1;
constexpr uint32_t k_max_delivery_workers = 256;

constexpr uint32_t k_min_sync_workers = 1;
constexpr uint32_t k_max_sync_workers = 128;

constexpr uint32_t k_min_queue_capacity = 16;
constexpr uint32_t k_max_queue_capacity = 65536;

constexpr uint32_t k_min_shutdown_grace_ms = 500;
constexpr uint32_t k_max_shutdown_grace_ms = 60000;

void parse_uint32(std::string_view key, const std::string& value, uint32_t& out_val,
                  common::configuration::ValidationResult& out_errors, uint32_t min_val, uint32_t max_val) {
    if (value.empty()) {
        out_errors.add_error(std::string(key), "value must not be empty");
        return;
    }
    try {
        size_t idx = 0;
        unsigned long val = std::stoul(value, &idx);
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

} // namespace

MessagingConfig MessagingConfig::load(const common::configuration::ConfigurationSource& source,
                                      common::configuration::ValidationResult& out_errors) {
    MessagingConfig config;
    config.common = common::configuration::CommonServiceConfig::load(source, "messaging", "Messaging Service",
                                                                     k_default_messaging_port, out_errors);

    // ScyllaDB host
    auto host_val = source.get("SECURECLOUD_MESSAGING_SCYLLA_HOST");
    if (host_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_MESSAGING_SCYLLA_HOST",
                                                                        host_val.value(), out_errors, false);
        if (parsed.has_value()) {
            config.scylla.host = parsed.value();
        }
    }

    // ScyllaDB port
    auto port_val = source.get("SECURECLOUD_MESSAGING_SCYLLA_PORT");
    if (port_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_uint16("SECURECLOUD_MESSAGING_SCYLLA_PORT",
                                                                        port_val.value(), out_errors);
        if (parsed.has_value()) {
            config.scylla.port = parsed.value();
        }
    } else {
        config.scylla.port = k_default_scylla_port;
    }

    // ScyllaDB keyspace
    auto keyspace_val = source.get("SECURECLOUD_MESSAGING_SCYLLA_KEYSPACE");
    if (keyspace_val.has_value()) {
        auto parsed = common::configuration::ConfigParser::parse_string("SECURECLOUD_MESSAGING_SCYLLA_KEYSPACE",
                                                                        keyspace_val.value(), out_errors, false);
        if (parsed.has_value()) {
            config.scylla.keyspace = parsed.value();
        }
    }

    // ScyllaDB timeouts and pool size
    auto connect_timeout_val = source.get("SECURECLOUD_MESSAGING_SCYLLA_CONNECT_TIMEOUT_MS");
    if (connect_timeout_val.has_value()) {
        parse_uint32("SECURECLOUD_MESSAGING_SCYLLA_CONNECT_TIMEOUT_MS", connect_timeout_val.value(),
                     config.scylla.connect_timeout_ms, out_errors, k_min_connect_timeout_ms, k_max_connect_timeout_ms);
    }

    auto request_timeout_val = source.get("SECURECLOUD_MESSAGING_SCYLLA_REQUEST_TIMEOUT_MS");
    if (request_timeout_val.has_value()) {
        parse_uint32("SECURECLOUD_MESSAGING_SCYLLA_REQUEST_TIMEOUT_MS", request_timeout_val.value(),
                     config.scylla.request_timeout_ms, out_errors, k_min_request_timeout_ms, k_max_request_timeout_ms);
    }

    auto pool_size_val = source.get("SECURECLOUD_MESSAGING_SCYLLA_CONNECTION_POOL_SIZE");
    if (pool_size_val.has_value()) {
        parse_uint32("SECURECLOUD_MESSAGING_SCYLLA_CONNECTION_POOL_SIZE", pool_size_val.value(),
                     config.scylla.connection_pool_size, out_errors, k_min_connection_pool_size,
                     k_max_connection_pool_size);
    }

    // Worker pool concurrency limits (ADR-009, ADR-010)
    auto sub_workers_val = source.get("SECURECLOUD_MESSAGING_SUBMISSION_WORKERS");
    if (sub_workers_val.has_value()) {
        parse_uint32("SECURECLOUD_MESSAGING_SUBMISSION_WORKERS", sub_workers_val.value(),
                     config.workers.submission_workers, out_errors, k_min_submission_workers, k_max_submission_workers);
    }

    auto del_workers_val = source.get("SECURECLOUD_MESSAGING_DELIVERY_WORKERS");
    if (del_workers_val.has_value()) {
        parse_uint32("SECURECLOUD_MESSAGING_DELIVERY_WORKERS", del_workers_val.value(), config.workers.delivery_workers,
                     out_errors, k_min_delivery_workers, k_max_delivery_workers);
    }

    auto sync_workers_val = source.get("SECURECLOUD_MESSAGING_SYNC_WORKERS");
    if (sync_workers_val.has_value()) {
        parse_uint32("SECURECLOUD_MESSAGING_SYNC_WORKERS", sync_workers_val.value(), config.workers.sync_workers,
                     out_errors, k_min_sync_workers, k_max_sync_workers);
    }

    // Queue capacities
    auto sub_queue_val = source.get("SECURECLOUD_MESSAGING_MAX_QUEUED_SUBMISSIONS");
    if (sub_queue_val.has_value()) {
        parse_uint32("SECURECLOUD_MESSAGING_MAX_QUEUED_SUBMISSIONS", sub_queue_val.value(),
                     config.workers.max_queued_submissions, out_errors, k_min_queue_capacity, k_max_queue_capacity);
    }

    auto del_queue_val = source.get("SECURECLOUD_MESSAGING_MAX_QUEUED_DELIVERIES");
    if (del_queue_val.has_value()) {
        parse_uint32("SECURECLOUD_MESSAGING_MAX_QUEUED_DELIVERIES", del_queue_val.value(),
                     config.workers.max_queued_deliveries, out_errors, k_min_queue_capacity, k_max_queue_capacity);
    }

    auto sync_queue_val = source.get("SECURECLOUD_MESSAGING_MAX_QUEUED_SYNCS");
    if (sync_queue_val.has_value()) {
        parse_uint32("SECURECLOUD_MESSAGING_MAX_QUEUED_SYNCS", sync_queue_val.value(), config.workers.max_queued_syncs,
                     out_errors, k_min_queue_capacity, k_max_queue_capacity);
    }

    // Shutdown grace period
    auto shutdown_val = source.get("SECURECLOUD_MESSAGING_SHUTDOWN_GRACE_PERIOD_MS");
    if (shutdown_val.has_value()) {
        parse_uint32("SECURECLOUD_MESSAGING_SHUTDOWN_GRACE_PERIOD_MS", shutdown_val.value(),
                     config.shutdown_grace_period_ms, out_errors, k_min_shutdown_grace_ms, k_max_shutdown_grace_ms);
    }

    // Keep direct compatibility fields in sync
    config.scylla_host = config.scylla.host;
    config.scylla_port = config.scylla.port;
    config.scylla_keyspace = config.scylla.keyspace;

    return config;
}

} // namespace securecloud::messaging
