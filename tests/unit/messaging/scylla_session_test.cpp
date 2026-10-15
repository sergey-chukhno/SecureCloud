#include "messaging/db/mock_scylla_session.hpp"
#include "messaging/db/scylla_error_mapper.hpp"
#include "messaging/db/scylla_params.hpp"
#include "messaging/db/scylla_session.hpp"
#include "messaging/db/scylla_session_pool.hpp"
#include "messaging/db/scylla_statement.hpp"
#include "messaging/db/scylla_types.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::messaging::db::test {
namespace {

// ============================================================================
// 1. ScyllaValue Tests
// ============================================================================

TEST(ScyllaValueTest, PrimitiveAndComplexTypeFidelity) {
    ScyllaValue null_val;
    EXPECT_TRUE(null_val.is_null());

    ScyllaValue str_val("conversation-123");
    EXPECT_FALSE(str_val.is_null());
    EXPECT_EQ(str_val.as_string(), "conversation-123");

    ScyllaValue int_val(42);
    EXPECT_EQ(int_val.as_int(), 42);
    EXPECT_EQ(int_val.as_int64(), 42);

    ScyllaValue int64_val(1700000000123LL);
    EXPECT_EQ(int64_val.as_int64(), 1700000000123LL);
    EXPECT_EQ(int64_val.as_timestamp(), 1700000000123LL);

    ScyllaValue bool_val(true);
    EXPECT_TRUE(bool_val.as_bool());

    std::vector<uint8_t> blob_data = {0xDE, 0xAD, 0xBE, 0xEF};
    ScyllaValue blob_val(blob_data);
    EXPECT_EQ(blob_val.as_blob(), blob_data);

    std::vector<std::string> str_list = {"user-1", "user-2"};
    ScyllaValue list_val(str_list);
    EXPECT_EQ(list_val.as_string_list(), str_list);
}

TEST(ScyllaValueTest, TypeMismatchThrowsBadVariantAccess) {
    ScyllaValue str_val("test-string");
    EXPECT_THROW((void)str_val.as_int(), std::bad_variant_access);
    EXPECT_THROW((void)str_val.as_bool(), std::bad_variant_access);
    EXPECT_THROW((void)str_val.as_blob(), std::bad_variant_access);

    ScyllaValue int_val(10);
    EXPECT_THROW((void)int_val.as_string(), std::bad_variant_access);
}

// ============================================================================
// 2. ScyllaRow & ScyllaQueryResult Tests
// ============================================================================

TEST(ScyllaRowTest, ColumnLookupAndTypeExtraction) {
    std::vector<std::string> cols = {"conv_id", "seq", "title", "active", "tags", "nullable_col"};
    std::vector<ScyllaValue> vals = {ScyllaValue("conv-001"),
                                     ScyllaValue(static_cast<int64_t>(105)),
                                     ScyllaValue("Project Alpha"),
                                     ScyllaValue(true),
                                     ScyllaValue(std::vector<std::string>{"tag1", "tag2"}),
                                     ScyllaValue::null()};

    ScyllaRow row(cols, vals);
    EXPECT_EQ(row.column_count(), 6U);
    EXPECT_EQ(row.get_string("conv_id"), "conv-001");
    EXPECT_EQ(row.get_int64("seq"), 105);
    EXPECT_EQ(row.get_string("title"), "Project Alpha");
    EXPECT_TRUE(row.get_bool("active"));
    EXPECT_EQ(row.get_string_list("tags").size(), 2U);
    EXPECT_TRUE(row.is_null("nullable_col"));
    EXPECT_FALSE(row.is_null("conv_id"));

    // Positional access
    EXPECT_EQ(row.get(0).as_string(), "conv-001");
    EXPECT_TRUE(row.is_null(5));

    // Unknown column throws out_of_range
    EXPECT_THROW((void)row.get("non_existent"), std::out_of_range);
    EXPECT_THROW((void)row.get(999), std::out_of_range);
}

TEST(ScyllaQueryResultTest, ResultIterationAndLwtAppliedFlag) {
    ScyllaRow r1({"id"}, {ScyllaValue("item-1")});
    ScyllaRow r2({"id"}, {ScyllaValue("item-2")});

    ScyllaQueryResult result({r1, r2}, /*is_applied=*/true);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result.size(), 2U);
    EXPECT_TRUE(result.is_applied());
    EXPECT_EQ(result.front().get_string("id"), "item-1");
    EXPECT_EQ(result[1].get_string("id"), "item-2");

    int count = 0;
    for (const auto& row : result) {
        EXPECT_FALSE(row.get_string("id").empty());
        ++count;
    }
    EXPECT_EQ(count, 2);

    result.set_applied(false);
    EXPECT_FALSE(result.is_applied());
}

// ============================================================================
// 3. ScyllaParams & BoundStatement Tests
// ============================================================================

TEST(ScyllaParamsTest, ParameterAccumulationAndTypePreservation) {
    ScyllaParams params;
    params.add_string("param1");
    params.add_int(100);
    params.add_int64(200000LL);
    params.add_timestamp(1700000000000LL);
    params.add_bool(false);
    params.add_null();

    EXPECT_EQ(params.size(), 6U);
    EXPECT_EQ(params[0].as_string(), "param1");
    EXPECT_EQ(params[1].as_int(), 100);
    EXPECT_EQ(params[2].as_int64(), 200000LL);
    EXPECT_EQ(params[3].as_timestamp(), 1700000000000LL);
    EXPECT_FALSE(params[4].as_bool());
    EXPECT_TRUE(params[5].is_null());
}

TEST(BoundStatementTest, StatementBindingAndConsistency) {
    PreparedStatementId id("query-find-conv");
    ScyllaParams params;
    params.add_string("conv-456");

    BoundStatement stmt(id, params, ConsistencyLevel::LocalQuorum);
    EXPECT_EQ(stmt.statement_id().value(), "query-find-conv");
    EXPECT_EQ(stmt.params().size(), 1U);
    EXPECT_EQ(stmt.consistency(), ConsistencyLevel::LocalQuorum);

    stmt.set_consistency(ConsistencyLevel::One);
    EXPECT_EQ(stmt.consistency(), ConsistencyLevel::One);
}

// ============================================================================
// 4. ScyllaErrorMapper Tests
// ============================================================================

TEST(ScyllaErrorMapperTest, ErrorCodeMappingToDomainAndGrpc) {
    EXPECT_EQ(ScyllaErrorMapper::to_domain_error_code(ScyllaErrorCode::ConnectionError), DomainErrorCode::Unavailable);
    EXPECT_EQ(ScyllaErrorMapper::to_grpc_status_code(ScyllaErrorCode::ConnectionError),
              ::grpc::StatusCode::UNAVAILABLE);

    EXPECT_EQ(ScyllaErrorMapper::to_domain_error_code(ScyllaErrorCode::Timeout), DomainErrorCode::DeadlineExceeded);
    EXPECT_EQ(ScyllaErrorMapper::to_grpc_status_code(ScyllaErrorCode::Timeout), ::grpc::StatusCode::DEADLINE_EXCEEDED);

    EXPECT_EQ(ScyllaErrorMapper::to_domain_error_code(ScyllaErrorCode::Overloaded), DomainErrorCode::ResourceExhausted);
    EXPECT_EQ(ScyllaErrorMapper::to_grpc_status_code(ScyllaErrorCode::Overloaded),
              ::grpc::StatusCode::RESOURCE_EXHAUSTED);
    EXPECT_EQ(ScyllaErrorMapper::to_messaging_error_code(ScyllaErrorCode::Overloaded),
              v1::MessagingErrorCode::MESSAGING_ERROR_CODE_QUEUE_CAPACITY_EXCEEDED);

    EXPECT_EQ(ScyllaErrorMapper::to_domain_error_code(ScyllaErrorCode::AlreadyExists), DomainErrorCode::AlreadyExists);
    EXPECT_EQ(ScyllaErrorMapper::to_grpc_status_code(ScyllaErrorCode::AlreadyExists),
              ::grpc::StatusCode::ALREADY_EXISTS);
    EXPECT_EQ(ScyllaErrorMapper::to_messaging_error_code(ScyllaErrorCode::AlreadyExists),
              v1::MessagingErrorCode::MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT);

    EXPECT_EQ(ScyllaErrorMapper::to_domain_error_code(ScyllaErrorCode::InvalidQuery), DomainErrorCode::InvalidArgument);
    EXPECT_EQ(ScyllaErrorMapper::to_grpc_status_code(ScyllaErrorCode::InvalidQuery),
              ::grpc::StatusCode::INVALID_ARGUMENT);

    EXPECT_EQ(ScyllaErrorMapper::to_domain_error_code(ScyllaErrorCode::Unauthorized),
              DomainErrorCode::PermissionDenied);
    EXPECT_EQ(ScyllaErrorMapper::to_grpc_status_code(ScyllaErrorCode::Unauthorized),
              ::grpc::StatusCode::PERMISSION_DENIED);

    EXPECT_EQ(ScyllaErrorMapper::to_domain_error_code(ScyllaErrorCode::InternalError), DomainErrorCode::Internal);
    EXPECT_EQ(ScyllaErrorMapper::to_grpc_status_code(ScyllaErrorCode::InternalError), ::grpc::StatusCode::INTERNAL);

    // Exception mapping
    ScyllaException ex(ScyllaErrorCode::Timeout, "Query timed out");
    EXPECT_EQ(ScyllaErrorMapper::to_domain_error_code(ex), DomainErrorCode::DeadlineExceeded);

    std::runtime_error std_ex("Generic error");
    EXPECT_EQ(ScyllaErrorMapper::to_domain_error_code(std_ex), DomainErrorCode::Internal);
}

// ============================================================================
// 5. MockScyllaSession Tests
// ============================================================================

TEST(MockScyllaSessionTest, ExecuteAndPreparedQueryMatching) {
    MockScyllaSession session;

    ScyllaRow row({"id", "type"}, {ScyllaValue("conv-001"), ScyllaValue("DIRECT")});
    ScyllaQueryResult expected_result({row});

    session.set_query_result("conversations_by_id", expected_result);

    // Ad-hoc execution
    auto res1 =
        session.execute("SELECT * FROM securecloud_messaging.conversations_by_id WHERE conversation_id = '123'");
    EXPECT_EQ(res1.size(), 1U);
    EXPECT_EQ(res1.front().get_string("type"), "DIRECT");

    // Prepared statement execution
    auto prep_id = session.prepare("find_conv_by_id",
                                   "SELECT * FROM securecloud_messaging.conversations_by_id WHERE conversation_id = ?");
    EXPECT_EQ(prep_id.value(), "find_conv_by_id");

    ScyllaParams params;
    params.add_string("conv-001");
    auto res2 = session.execute_prepared(prep_id, params);
    EXPECT_EQ(res2.size(), 1U);
    EXPECT_EQ(res2.front().get_string("id"), "conv-001");

    // History verification
    EXPECT_EQ(session.get_executed_queries().size(), 1U);
    EXPECT_EQ(session.get_executed_prepared().size(), 1U);
}

TEST(MockScyllaSessionTest, BatchExecutionAndCustomHandler) {
    MockScyllaSession session;

    auto prep1 = session.prepare("q1", "INSERT INTO t1 (id) VALUES (?)");
    auto prep2 = session.prepare("q2", "INSERT INTO t2 (id) VALUES (?)");

    ScyllaParams p1;
    p1.add_string("id-1");
    ScyllaParams p2;
    p2.add_string("id-2");

    std::vector<BoundStatement> batch = {BoundStatement(prep1, p1), BoundStatement(prep2, p2)};

    session.execute_batch(batch, BatchType::Logged);
    EXPECT_EQ(session.get_executed_batches().size(), 1U);
    EXPECT_EQ(session.get_executed_batches()[0].size(), 2U);

    // Custom handler
    session.set_custom_handler([](std::string_view cql, const ScyllaParams* params) {
        if (cql.find("custom_table") != std::string::npos && params && !params->empty()) {
            return ScyllaQueryResult({ScyllaRow({"ret"}, {ScyllaValue("custom-ok")})});
        }
        return ScyllaQueryResult{};
    });

    auto prep_custom = session.prepare("custom_q", "SELECT * FROM custom_table WHERE k = ?");
    ScyllaParams cp;
    cp.add_string("val");
    auto custom_res = session.execute_prepared(prep_custom, cp);
    EXPECT_EQ(custom_res.size(), 1U);
    EXPECT_EQ(custom_res.front().get_string("ret"), "custom-ok");
}

TEST(MockScyllaSessionTest, FaultInjectionAndClosedState) {
    MockScyllaSession session;
    session.set_fail_on_execute(true, ScyllaErrorCode::Timeout, "Simulated driver timeout");

    EXPECT_THROW({ session.execute("SELECT 1"); }, ScyllaException);

    PreparedStatementId pid("test-prep");
    EXPECT_THROW({ session.execute_prepared(pid, ScyllaParams{}); }, ScyllaException);

    session.set_fail_on_execute(false);
    session.close();
    EXPECT_TRUE(session.is_closed());

    EXPECT_THROW({ session.execute("SELECT 1"); }, ScyllaException);
}

// ============================================================================
// 6. SessionPool & PooledScyllaSession Tests
// ============================================================================

TEST(SessionPoolTest, MockSessionPoolAcquireReleaseAndHealth) {
    auto mock_sess = std::make_shared<MockScyllaSession>();
    MockScyllaSessionPool pool(mock_sess);

    EXPECT_TRUE(pool.ping());
    EXPECT_EQ(pool.size(), 1U);
    EXPECT_EQ(pool.active_count(), 0U);

    {
        auto session = pool.acquire();
        EXPECT_EQ(pool.active_count(), 1U);
        EXPECT_EQ(session.get(), mock_sess.get());
        pool.release(session);
    }
    EXPECT_EQ(pool.active_count(), 0U);

    // Acquire failure simulation
    pool.set_acquire_failure(true);
    EXPECT_THROW({ pool.acquire(); }, ScyllaException);
}

TEST(SessionPoolTest, ScyllaSessionPoolLifecycleAndRAIILease) {
    ScyllaConfig config;
    config.host = "127.0.0.1";
    config.port = 9042;
    config.connection_pool_size = 2;

    ScyllaSessionPool pool(config);
    EXPECT_EQ(pool.size(), 2U);
    EXPECT_EQ(pool.active_count(), 0U);

    {
        auto lease1 = pool.acquire_lease(std::chrono::milliseconds(500));
        EXPECT_EQ(pool.active_count(), 1U);

        auto lease2 = pool.acquire_lease(std::chrono::milliseconds(500));
        EXPECT_EQ(pool.active_count(), 2U);

        // Pool is now exhausted (size = 2, active = 2)
        EXPECT_THROW({ (void)pool.acquire_lease(std::chrono::milliseconds(50)); }, ScyllaException);
    }

    // Leases went out of scope: active count restored to 0
    EXPECT_EQ(pool.active_count(), 0U);
}

} // namespace
} // namespace securecloud::messaging::db::test
