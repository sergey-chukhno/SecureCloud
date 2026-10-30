#include "repository/clickhouse_query_builder.hpp"

#include <gtest/gtest.h>
#include <chrono>

namespace securecloud::audit::repository::testing {

class ClickHouseQueryBuilderTest : public ::testing::Test {
  protected:
    query::AuditQueryFilter build_sample_filter() {
        query::AuditQueryFilter filter;
        filter.start_occurred_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(1710000000000LL));
        filter.end_occurred_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(1710086400000LL));
        filter.producer_services = {domain::ProducerService::Auth, domain::ProducerService::Gateway};
        filter.event_types = {"user.login", "user.logout"};
        filter.severities = {domain::Severity::Info, domain::Severity::Security};
        filter.actor_type = domain::ActorType::User;
        filter.actor_id = "user-123";
        filter.target_type = domain::TargetType::Service;
        filter.target_id = "sys-01";
        filter.correlation_id = "corr-99";
        filter.page_size = 50;
        filter.sort_order = query::SortOrder::Descending;
        return filter;
    }
};

TEST_F(ClickHouseQueryBuilderTest, BuildMinimalFilterQuery) {
    query::AuditQueryFilter filter;
    filter.start_occurred_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(1710000000000LL));
    filter.end_occurred_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(1710086400000LL));
    filter.page_size = 100;
    filter.sort_order = query::SortOrder::Descending;

    auto query = ClickHouseQueryBuilder::build_filter_query(filter);

    // SQL Template Assertions
    EXPECT_NE(query.sql_template.find("occurred_at >= fromUnixTimestamp64Milli({start_ms:Int64})"), std::string::npos);
    EXPECT_NE(query.sql_template.find("occurred_at < fromUnixTimestamp64Milli({end_ms:Int64})"), std::string::npos);
    EXPECT_NE(query.sql_template.find("ORDER BY occurred_at DESC, producer_service DESC, event_type DESC, event_id DESC"), std::string::npos);
    EXPECT_NE(query.sql_template.find("LIMIT 1 BY event_id"), std::string::npos);
    EXPECT_NE(query.sql_template.find("LIMIT {limit_plus_one:UInt32} FORMAT TabSeparated"), std::string::npos);

    // Bind Parameters Assertions
    EXPECT_EQ(query.bind_params.at("start_ms"), "1710000000000");
    EXPECT_EQ(query.bind_params.at("end_ms"), "1710086400000");
    EXPECT_EQ(query.bind_params.at("limit_plus_one"), "101"); // page_size + 1 for lookahead
}

TEST_F(ClickHouseQueryBuilderTest, BuildFilterQueryWithAllParametersAndCursor) {
    auto filter = build_sample_filter();

    query::AuditPageCursor cursor;
    cursor.last_occurred_at_ms = 1710050000000LL;
    cursor.last_producer_service = "auth";
    cursor.last_event_type = "user.login";
    cursor.last_event_id = domain::EventId::from_string("018f6e4a-7b3c-7000-8000-000000000001").value();

    auto query = ClickHouseQueryBuilder::build_filter_query(filter, cursor);

    // Predicate checks in SQL Template
    EXPECT_NE(query.sql_template.find("producer_service IN ({producer_0:String}, {producer_1:String})"), std::string::npos);
    EXPECT_NE(query.sql_template.find("event_type IN ({event_type_0:String}, {event_type_1:String})"), std::string::npos);
    EXPECT_NE(query.sql_template.find("severity IN ({severity_0:String}, {severity_1:String})"), std::string::npos);
    EXPECT_NE(query.sql_template.find("actor_type = {actor_type:String} AND actor_id = {actor_id:String}"), std::string::npos);
    EXPECT_NE(query.sql_template.find("target_type = {target_type:String} AND target_id = {target_id:String}"), std::string::npos);
    EXPECT_NE(query.sql_template.find("correlation_id = {correlation_id:String}"), std::string::npos);

    // Keyset Tuple Predicate check for Descending
    EXPECT_NE(query.sql_template.find("(occurred_at, producer_service, event_type, event_id) < (fromUnixTimestamp64Milli({cursor_ts:Int64}), {cursor_prod:String}, {cursor_type:String}, {cursor_id:UUID})"), std::string::npos);

    // Parameter value bindings
    EXPECT_EQ(query.bind_params.at("start_ms"), "1710000000000");
    EXPECT_EQ(query.bind_params.at("end_ms"), "1710086400000");
    EXPECT_EQ(query.bind_params.at("producer_0"), "auth");
    EXPECT_EQ(query.bind_params.at("producer_1"), "gateway");
    EXPECT_EQ(query.bind_params.at("event_type_0"), "user.login");
    EXPECT_EQ(query.bind_params.at("event_type_1"), "user.logout");
    EXPECT_EQ(query.bind_params.at("actor_type"), "USER");
    EXPECT_EQ(query.bind_params.at("actor_id"), "user-123");
    EXPECT_EQ(query.bind_params.at("target_type"), "SERVICE");
    EXPECT_EQ(query.bind_params.at("target_id"), "sys-01");
    EXPECT_EQ(query.bind_params.at("correlation_id"), "corr-99");
    EXPECT_EQ(query.bind_params.at("cursor_ts"), "1710050000000");
    EXPECT_EQ(query.bind_params.at("cursor_prod"), "auth");
    EXPECT_EQ(query.bind_params.at("cursor_type"), "user.login");
    EXPECT_EQ(query.bind_params.at("cursor_id"), "018f6e4a-7b3c-7000-8000-000000000001");
    EXPECT_EQ(query.bind_params.at("limit_plus_one"), "51");
}

TEST_F(ClickHouseQueryBuilderTest, BuildFilterQueryAscendingOrder) {
    auto filter = build_sample_filter();
    filter.sort_order = query::SortOrder::Ascending;

    query::AuditPageCursor cursor;
    cursor.last_occurred_at_ms = 1710050000000LL;
    cursor.last_producer_service = "auth";
    cursor.last_event_type = "user.login";
    cursor.last_event_id = domain::EventId::from_string("018f6e4a-7b3c-7000-8000-000000000001").value();

    auto query = ClickHouseQueryBuilder::build_filter_query(filter, cursor);

    // Keyset Tuple Predicate check for Ascending (uses > instead of <)
    EXPECT_NE(query.sql_template.find("(occurred_at, producer_service, event_type, event_id) > (fromUnixTimestamp64Milli({cursor_ts:Int64}), {cursor_prod:String}, {cursor_type:String}, {cursor_id:UUID})"), std::string::npos);
    EXPECT_NE(query.sql_template.find("ORDER BY occurred_at ASC, producer_service ASC, event_type ASC, event_id ASC"), std::string::npos);
}

TEST_F(ClickHouseQueryBuilderTest, BuildGetByIdQueryWithPartitionPruning) {
    auto id = domain::EventId::from_string("018f6e4a-7b3c-7000-8000-000000000001").value();
    auto query = ClickHouseQueryBuilder::build_get_by_id_query(id);

    // SQL Template verification
    EXPECT_NE(query.sql_template.find("occurred_at >= fromUnixTimestamp64Milli({uuid_ts_min:Int64})"), std::string::npos);
    EXPECT_NE(query.sql_template.find("occurred_at <= fromUnixTimestamp64Milli({uuid_ts_max:Int64})"), std::string::npos);
    EXPECT_NE(query.sql_template.find("event_id = {event_id:UUID} LIMIT 1 FORMAT TabSeparated"), std::string::npos);

    // Parameter bindings
    EXPECT_EQ(query.bind_params.at("event_id"), "018f6e4a-7b3c-7000-8000-000000000001");

    // Partition pruning 20-minute skew window check (+/- 10 minutes = 1,200,000 ms)
    int64_t min_ts = std::stoll(query.bind_params.at("uuid_ts_min"));
    int64_t max_ts = std::stoll(query.bind_params.at("uuid_ts_max"));
    uint64_t embedded_ts = id.timestamp_ms();

    EXPECT_EQ(min_ts, static_cast<int64_t>(embedded_ts - 600000));
    EXPECT_EQ(max_ts, static_cast<int64_t>(embedded_ts + 600000));
    EXPECT_EQ(max_ts - min_ts, 1200000);
}

} // namespace securecloud::audit::repository::testing