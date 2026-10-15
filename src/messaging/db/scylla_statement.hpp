#pragma once

#include "messaging/db/scylla_params.hpp"

#include <string>
#include <utility>

namespace securecloud::messaging::db {

/// CQL Consistency Levels supported by ScyllaDB.
enum class ConsistencyLevel {
    Any,
    One,
    Two,
    Three,
    Quorum,
    All,
    LocalQuorum, // Recommended default for M3
    EachQuorum,
    Serial,
    LocalSerial,
    LocalOne
};

/// CQL Batch types for multi-statement execution.
enum class BatchType {
    Logged,   // Atomic batch
    Unlogged, // Distributed batch without coordinator log
    Counter
};

/// Strongly-typed identifier for cached prepared statements.
struct PreparedStatementId {
    std::string id;

    PreparedStatementId() = default;
    explicit PreparedStatementId(std::string identifier) : id(std::move(identifier)) {}

    [[nodiscard]] const std::string& value() const noexcept { return id; }
    bool operator==(const PreparedStatementId& other) const = default;
};

/// Pairs a prepared statement with bound parameters and target consistency.
class BoundStatement {
  public:
    BoundStatement(PreparedStatementId id, ScyllaParams params, ConsistencyLevel cl = ConsistencyLevel::LocalQuorum)
        : statement_id_(std::move(id)), params_(std::move(params)), consistency_(cl) {}

    [[nodiscard]] const PreparedStatementId& statement_id() const noexcept { return statement_id_; }
    [[nodiscard]] const ScyllaParams& params() const noexcept { return params_; }
    [[nodiscard]] ConsistencyLevel consistency() const noexcept { return consistency_; }

    void set_consistency(ConsistencyLevel cl) noexcept { consistency_ = cl; }

  private:
    PreparedStatementId statement_id_;
    ScyllaParams params_;
    ConsistencyLevel consistency_{ConsistencyLevel::LocalQuorum};
};

} // namespace securecloud::messaging::db
