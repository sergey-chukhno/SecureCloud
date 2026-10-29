#pragma once

#include "messaging/db/scylla_error_mapper.hpp"
#include "messaging/db/scylla_session_interface.hpp"

#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace securecloud::messaging::db {

/// High-fidelity in-memory mock session for hermetic unit testing.
class MockScyllaSession : public IScyllaSession {
  public:
    using QueryHandler = std::function<ScyllaQueryResult(std::string_view cql, const ScyllaParams* params)>;

    MockScyllaSession() = default;

    ScyllaQueryResult execute(std::string_view cql, ConsistencyLevel cl = ConsistencyLevel::LocalQuorum) override;

    PreparedStatementId prepare(std::string_view query_id, std::string_view cql) override;

    ScyllaQueryResult execute_prepared(const PreparedStatementId& id, const ScyllaParams& params,
                                       ConsistencyLevel cl = ConsistencyLevel::LocalQuorum) override;

    void execute_batch(const std::vector<BoundStatement>& batch, BatchType type = BatchType::Logged) override;

    bool ping() override;
    void close() override;
    [[nodiscard]] bool is_closed() const noexcept override;

    // --- Mock Configuration & Test Inspection Helpers ---

    void set_query_result(const std::string& query_substring, ScyllaQueryResult result);
    void set_prepared_result(const PreparedStatementId& id, ScyllaQueryResult result);
    void set_custom_handler(QueryHandler handler);

    void set_fail_on_execute(bool fail, ScyllaErrorCode code = ScyllaErrorCode::InternalError,
                             std::string message = "Injected mock error");
    void set_ping_healthy(bool healthy) noexcept;

    [[nodiscard]] std::unordered_map<std::string, std::string> get_prepared_statements() const;
    [[nodiscard]] std::vector<std::string> get_executed_queries();
    [[nodiscard]] std::vector<std::pair<PreparedStatementId, ScyllaParams>> get_executed_prepared();
    [[nodiscard]] std::vector<std::vector<BoundStatement>> get_executed_batches();

    void clear_history();

  private:
    mutable std::mutex mutex_;
    bool closed_{false};
    bool ping_healthy_{true};

    bool fail_on_execute_{false};
    ScyllaErrorCode injected_error_code_{ScyllaErrorCode::InternalError};
    std::string injected_error_message_{"Injected mock error"};

    std::unordered_map<std::string, std::string> prepared_statements_;
    std::unordered_map<std::string, ScyllaQueryResult> query_substring_results_;
    std::unordered_map<std::string, ScyllaQueryResult> prepared_results_;
    QueryHandler custom_handler_;

    std::vector<std::string> executed_queries_;
    std::vector<std::pair<PreparedStatementId, ScyllaParams>> executed_prepared_;
    std::vector<std::vector<BoundStatement>> executed_batches_;
};

/// Mock session pool returning MockScyllaSession instances.
class MockScyllaSessionPool : public IScyllaSessionPool {
  public:
    explicit MockScyllaSessionPool(std::shared_ptr<MockScyllaSession> session = nullptr);

    std::shared_ptr<IScyllaSession>
    acquire(std::chrono::milliseconds timeout = std::chrono::milliseconds(5000)) override;

    void release(std::shared_ptr<IScyllaSession> session) override;

    [[nodiscard]] std::size_t size() const noexcept override;
    [[nodiscard]] std::size_t active_count() const noexcept override;
    bool ping() override;
    void close() override;

    void set_acquire_failure(bool fail);
    [[nodiscard]] std::shared_ptr<MockScyllaSession> mock_session() const noexcept { return session_; }

  private:
    std::shared_ptr<MockScyllaSession> session_;
    bool fail_acquire_{false};
    std::size_t active_{0};
    mutable std::mutex mutex_;
};

} // namespace securecloud::messaging::db
