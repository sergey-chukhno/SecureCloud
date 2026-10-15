#pragma once

#include "messaging/db/scylla_session_interface.hpp"
#include "messaging/messaging_config.hpp"

#include <mutex>
#include <string>
#include <unordered_map>

namespace securecloud::messaging::db {

/// Production implementation of IScyllaSession.
class ScyllaSession : public IScyllaSession {
  public:
    explicit ScyllaSession(ScyllaConfig config);
    ~ScyllaSession() override;

    ScyllaQueryResult execute(std::string_view cql, ConsistencyLevel cl = ConsistencyLevel::LocalQuorum) override;

    PreparedStatementId prepare(std::string_view query_id, std::string_view cql) override;

    ScyllaQueryResult execute_prepared(const PreparedStatementId& id, const ScyllaParams& params,
                                       ConsistencyLevel cl = ConsistencyLevel::LocalQuorum) override;

    void execute_batch(const std::vector<BoundStatement>& batch, BatchType type = BatchType::Logged) override;

    bool ping() override;
    void close() override;
    [[nodiscard]] bool is_closed() const noexcept override;

    [[nodiscard]] const ScyllaConfig& config() const noexcept { return config_; }

  private:
    void ensure_connected();

    ScyllaConfig config_;
    bool closed_{false};
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::string> prepared_cache_;
};

} // namespace securecloud::messaging::db
