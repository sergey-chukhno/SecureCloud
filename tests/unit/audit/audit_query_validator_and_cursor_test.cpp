#include "query/audit_page_cursor.hpp"
#include "query/audit_query_validator.hpp"
#include "repository/clickhouse_query_builder.hpp"

#include <gtest/gtest.h>
#include <chrono>

namespace securecloud::audit::query::testing {

class AuditQueryValidatorAndCursorTest : public ::testing::Test {
  protected:
    void SetUp() override {
        config_.default_time_window_hours = 24;
        config_.max_time_window_hours = 744; // 31 days
        config_.default_page_limit = 100;
        config_.max_page_limit = 1000;
        config_.query_timeout_ms = 10000;
        config_.workers = 4;
        config_.max_result_bytes = 16777216;
    }

    QueryConfig config_;
};

TEST_F(AuditQueryValidatorAndCursorTest, ValidFilterAndDefaultWindowPasses) {
    AuditQueryFilter filter;
    auto now = std::chrono::system_clock::now();

    auto status = AuditQueryValidator::validate_and_normalize(filter, config_, now);

    EXPECT_TRUE(status.ok());
    EXPECT_TRUE(filter.start_occurred_at.has_value());
    EXPECT_TRUE(filter.end_occurred_at.has_value());
    EXPECT_EQ(filter.page_size, config_.default_page_limit);
    EXPECT_LT(*filter.start_occurred_at, *filter.end_occurred_at);
}

TEST_F(AuditQueryValidatorAndCursorTest, RejectsInvertedAndExcessiveTimeWindows) {
    auto now = std::chrono::system_clock::now();

    // 1. Inverted time window (start >= end)
    AuditQueryFilter inverted_filter;
    inverted_filter.start_occurred_at = now;
    inverted_filter.end_occurred_at = now - std::chrono::hours(1);
    auto status_inverted = AuditQueryValidator::validate_and_normalize(inverted_filter, config_, now);
    EXPECT_EQ(status_inverted.error_code(), grpc::StatusCode::INVALID_ARGUMENT);

    // 2. Excessive time window (> 31 days)
    AuditQueryFilter excessive_filter;
    excessive_filter.start_occurred_at = now - std::chrono::hours(745);
    excessive_filter.end_occurred_at = now;
    auto status_excessive = AuditQueryValidator::validate_and_normalize(excessive_filter, config_, now);
    EXPECT_EQ(status_excessive.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST_F(AuditQueryValidatorAndCursorTest, RejectsOversizedPageLimit) {
    AuditQueryFilter filter;
    filter.page_size = 1001; // exceeds max_page_limit of 1000

    auto status = AuditQueryValidator::validate_and_normalize(filter, config_);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST_F(AuditQueryValidatorAndCursorTest, CursorRoundtripAndFilterTamperDetection) {
    AuditQueryFilter filter;
    filter.producer_services = {domain::ProducerService::Auth};
    filter.severities = {domain::Severity::Security};

    AuditPageCursor original_cursor;
    original_cursor.last_occurred_at_ms = 1710000000000LL;
    original_cursor.last_producer_service = "auth";
    original_cursor.last_event_type = "user.login";
    original_cursor.last_event_id = domain::EventId::generate_v7();
    original_cursor.filter_hash = AuditPageCursorCodec::compute_filter_hash(filter);

    std::string encoded_token = AuditPageCursorCodec::encode(original_cursor);
    EXPECT_FALSE(encoded_token.empty());

    // 1. Valid decoding with identical filter
    auto expected_hash = AuditPageCursorCodec::compute_filter_hash(filter);
    auto decoded_opt = AuditPageCursorCodec::decode(encoded_token, expected_hash);
    ASSERT_TRUE(decoded_opt.has_value());
    EXPECT_EQ(decoded_opt->last_occurred_at_ms, original_cursor.last_occurred_at_ms);

    // 2. Tampered filter detection (changing severity)
    AuditQueryFilter tampered_filter = filter;
    tampered_filter.severities = {domain::Severity::Critical};
    auto tampered_hash = AuditPageCursorCodec::compute_filter_hash(tampered_filter);

    auto tampered_decoded = AuditPageCursorCodec::decode(encoded_token, tampered_hash);
    EXPECT_FALSE(tampered_decoded.has_value());
}

TEST_F(AuditQueryValidatorAndCursorTest, SqlMetacharacterAndInjectionStringsRejectedAtValidationAndBoundSafely) {
    AuditQueryFilter malicious_filter;
    malicious_filter.start_occurred_at = std::chrono::system_clock::now() - std::chrono::hours(1);
    malicious_filter.end_occurred_at = std::chrono::system_clock::now();
    malicious_filter.actor_type = domain::ActorType::User;
    malicious_filter.actor_id = "user1' OR '1'='1; DROP TABLE audit_events; --";

    // 1. Rejection at validation layer
    auto status = AuditQueryValidator::validate_and_normalize(malicious_filter, config_);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);

    // 2. Query builder parameter binding isolation check
    auto query = repository::ClickHouseQueryBuilder::build_filter_query(malicious_filter);
    EXPECT_EQ(query.sql_template.find("DROP TABLE"), std::string::npos);
    EXPECT_EQ(query.bind_params.at("actor_id"), "user1' OR '1'='1; DROP TABLE audit_events; --");
}

} // namespace securecloud::audit::query::testing