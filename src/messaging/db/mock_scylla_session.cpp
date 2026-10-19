#include "messaging/db/mock_scylla_session.hpp"

#include <algorithm>

namespace securecloud::messaging::db {

ScyllaQueryResult MockScyllaSession::execute(std::string_view cql, ConsistencyLevel /*cl*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_) {
        throw ScyllaException(ScyllaErrorCode::ConnectionError, "Session is closed");
    }
    if (fail_on_execute_) {
        throw ScyllaException(injected_error_code_, injected_error_message_);
    }

    std::string cql_str(cql);
    executed_queries_.push_back(cql_str);

    if (custom_handler_) {
        return custom_handler_(cql, nullptr);
    }

    // Check substring match
    for (const auto& [pattern, result] : query_substring_results_) {
        if (cql_str.find(pattern) != std::string::npos) {
            return result;
        }
    }

    return ScyllaQueryResult{};
}

PreparedStatementId MockScyllaSession::prepare(std::string_view query_id, std::string_view cql) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_) {
        throw ScyllaException(ScyllaErrorCode::ConnectionError, "Session is closed");
    }
    std::string id_str(query_id);
    prepared_statements_[id_str] = std::string(cql);
    return PreparedStatementId(id_str);
}

ScyllaQueryResult MockScyllaSession::execute_prepared(const PreparedStatementId& id, const ScyllaParams& params,
                                                      ConsistencyLevel /*cl*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_) {
        throw ScyllaException(ScyllaErrorCode::ConnectionError, "Session is closed");
    }
    if (fail_on_execute_) {
        throw ScyllaException(injected_error_code_, injected_error_message_);
    }

    executed_prepared_.emplace_back(id, params);

    // Check registered prepared result
    auto it = prepared_results_.find(id.value());
    if (it != prepared_results_.end()) {
        return it->second;
    }

    // Check cql for prepared id
    auto cql_it = prepared_statements_.find(id.value());
    if (cql_it != prepared_statements_.end()) {
        if (custom_handler_) {
            return custom_handler_(cql_it->second, &params);
        }
        for (const auto& [pattern, result] : query_substring_results_) {
            if (cql_it->second.find(pattern) != std::string::npos) {
                return result;
            }
        }
    }

    return ScyllaQueryResult{};
}

void MockScyllaSession::execute_batch(const std::vector<BoundStatement>& batch, BatchType /*type*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_) {
        throw ScyllaException(ScyllaErrorCode::ConnectionError, "Session is closed");
    }
    if (fail_on_execute_) {
        throw ScyllaException(injected_error_code_, injected_error_message_);
    }

    executed_batches_.push_back(batch);
}

bool MockScyllaSession::ping() {
    std::lock_guard<std::mutex> lock(mutex_);
    return !closed_ && ping_healthy_;
}

void MockScyllaSession::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    closed_ = true;
}

bool MockScyllaSession::is_closed() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return closed_;
}

void MockScyllaSession::set_query_result(const std::string& query_substring, ScyllaQueryResult result) {
    std::lock_guard<std::mutex> lock(mutex_);
    query_substring_results_[query_substring] = std::move(result);
}

void MockScyllaSession::set_prepared_result(const PreparedStatementId& id, ScyllaQueryResult result) {
    std::lock_guard<std::mutex> lock(mutex_);
    prepared_results_[id.value()] = std::move(result);
}

void MockScyllaSession::set_custom_handler(QueryHandler handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    custom_handler_ = std::move(handler);
}

void MockScyllaSession::set_fail_on_execute(bool fail, ScyllaErrorCode code, std::string message) {
    std::lock_guard<std::mutex> lock(mutex_);
    fail_on_execute_ = fail;
    injected_error_code_ = code;
    injected_error_message_ = std::move(message);
}

void MockScyllaSession::set_ping_healthy(bool healthy) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    ping_healthy_ = healthy;
}

std::vector<std::string> MockScyllaSession::get_executed_queries() {
    std::lock_guard<std::mutex> lock(mutex_);
    return executed_queries_;
}

std::vector<std::pair<PreparedStatementId, ScyllaParams>> MockScyllaSession::get_executed_prepared() {
    std::lock_guard<std::mutex> lock(mutex_);
    return executed_prepared_;
}

std::vector<std::vector<BoundStatement>> MockScyllaSession::get_executed_batches() {
    std::lock_guard<std::mutex> lock(mutex_);
    return executed_batches_;
}

void MockScyllaSession::clear_history() {
    std::lock_guard<std::mutex> lock(mutex_);
    executed_queries_.clear();
    executed_prepared_.clear();
    executed_batches_.clear();
}

MockScyllaSessionPool::MockScyllaSessionPool(std::shared_ptr<MockScyllaSession> session)
    : session_(session ? session : std::make_shared<MockScyllaSession>()) {}

std::shared_ptr<IScyllaSession> MockScyllaSessionPool::acquire(std::chrono::milliseconds /*timeout*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (fail_acquire_) {
        throw ScyllaException(ScyllaErrorCode::Timeout, "Pool acquire timed out (simulated)");
    }
    ++active_;
    return session_;
}

void MockScyllaSessionPool::release(std::shared_ptr<IScyllaSession> /*session*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (active_ > 0) {
        --active_;
    }
}

std::size_t MockScyllaSessionPool::size() const noexcept {
    return 1;
}

std::size_t MockScyllaSessionPool::active_count() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_;
}

bool MockScyllaSessionPool::ping() {
    return session_->ping();
}

void MockScyllaSessionPool::close() {
    session_->close();
}

void MockScyllaSessionPool::set_acquire_failure(bool fail) {
    std::lock_guard<std::mutex> lock(mutex_);
    fail_acquire_ = fail;
}

} // namespace securecloud::messaging::db
