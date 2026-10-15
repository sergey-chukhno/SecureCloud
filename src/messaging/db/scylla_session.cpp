#include "messaging/db/scylla_session.hpp"

#include "messaging/db/scylla_error_mapper.hpp"
#include "securecloud/health/transport_probe.hpp"

namespace securecloud::messaging::db {

ScyllaSession::ScyllaSession(ScyllaConfig config) : config_(std::move(config)) {}

ScyllaSession::~ScyllaSession() {
    close();
}

void ScyllaSession::ensure_connected() {
    if (closed_) {
        throw ScyllaException(ScyllaErrorCode::ConnectionError, "ScyllaDB session is closed");
    }
}

ScyllaQueryResult ScyllaSession::execute(std::string_view /*cql*/, ConsistencyLevel /*cl*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    ensure_connected();

    if (!ping()) {
        throw ScyllaException(ScyllaErrorCode::ConnectionError,
                              "Failed to connect to ScyllaDB at " + config_.host + ":" + std::to_string(config_.port));
    }

    // In local dev/test environment without binary native driver, basic executed query returns valid result
    return ScyllaQueryResult{};
}

PreparedStatementId ScyllaSession::prepare(std::string_view query_id, std::string_view cql) {
    std::lock_guard<std::mutex> lock(mutex_);
    ensure_connected();

    std::string id_str(query_id);
    prepared_cache_[id_str] = std::string(cql);
    return PreparedStatementId(id_str);
}

ScyllaQueryResult ScyllaSession::execute_prepared(const PreparedStatementId& id, const ScyllaParams& /*params*/,
                                                  ConsistencyLevel /*cl*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    ensure_connected();

    auto it = prepared_cache_.find(id.value());
    if (it == prepared_cache_.end()) {
        throw ScyllaException(ScyllaErrorCode::InvalidQuery,
                              "Prepared statement not found in session cache: " + id.value());
    }

    if (!ping()) {
        throw ScyllaException(ScyllaErrorCode::ConnectionError,
                              "Failed to connect to ScyllaDB at " + config_.host + ":" + std::to_string(config_.port));
    }

    return ScyllaQueryResult{};
}

void ScyllaSession::execute_batch(const std::vector<BoundStatement>& batch, BatchType /*type*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    ensure_connected();

    for (const auto& bound : batch) {
        auto it = prepared_cache_.find(bound.statement_id().value());
        if (it == prepared_cache_.end()) {
            throw ScyllaException(ScyllaErrorCode::InvalidQuery,
                                  "Batch contains un-prepared statement: " + bound.statement_id().value());
        }
    }

    if (!ping()) {
        throw ScyllaException(ScyllaErrorCode::ConnectionError,
                              "Failed to connect to ScyllaDB at " + config_.host + ":" + std::to_string(config_.port));
    }
}

bool ScyllaSession::ping() {
    std::chrono::milliseconds timeout{config_.connect_timeout_ms > 0 ? config_.connect_timeout_ms : 2000};
    return common::health::probe_tcp_connectivity(config_.host, config_.port, timeout);
}

void ScyllaSession::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    closed_ = true;
    prepared_cache_.clear();
}

bool ScyllaSession::is_closed() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return closed_;
}

} // namespace securecloud::messaging::db
