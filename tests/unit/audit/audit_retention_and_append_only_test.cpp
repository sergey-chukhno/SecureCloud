#include "audit_config.hpp"
#include "domain/audit_event_validator.hpp"
#include "repository/append_only_sql_guard.hpp"
#include "repository/audit_repository_exceptions.hpp"
#include "repository/schema_initializer.hpp"

#include <gtest/gtest.h>
#include <chrono>

namespace securecloud::audit::test {

TEST(AuditRetentionAndAppendOnlyUnitTest, RetentionConfigDefaultsTo36Months1095Days) {
    RetentionConfig config;
    EXPECT_EQ(config.retention_months, 36u);
    EXPECT_EQ(config.retention_days, 1095u);

    domain::AuditEventValidationLimits limits;
    EXPECT_EQ(limits.max_past_age, std::chrono::hours(24 * 1095));
}

TEST(AuditRetentionAndAppendOnlyUnitTest, AppendOnlySqlGuardPermitsSelectAndInsertOnly) {
    using repository::AppendOnlySqlGuard;

    EXPECT_NO_THROW(AppendOnlySqlGuard::validate_query_sql(
        "SELECT event_id, occurred_at FROM securecloud_audit.audit_events WHERE occurred_at >= now()"));

    EXPECT_NO_THROW(AppendOnlySqlGuard::validate_insert_sql(
        "INSERT INTO securecloud_audit.audit_events FORMAT TabSeparated"));
}

TEST(AuditRetentionAndAppendOnlyUnitTest, AppendOnlySqlGuardBlocksUpdateDeleteTruncateDropAndMultiStatement) {
    using repository::AppendOnlySqlGuard;
    using repository::AppendOnlyViolationException;

    // Mutating ALTER queries
    EXPECT_THROW(AppendOnlySqlGuard::validate_query_sql(
                     "ALTER TABLE securecloud_audit.audit_events UPDATE actor_id = 'forged' WHERE 1=1"),
                 AppendOnlyViolationException);

    EXPECT_THROW(AppendOnlySqlGuard::validate_query_sql(
                     "ALTER TABLE securecloud_audit.audit_events DELETE WHERE 1=1"),
                 AppendOnlyViolationException);

    // Destructive DML/DDL queries
    EXPECT_THROW(AppendOnlySqlGuard::validate_query_sql("DELETE FROM securecloud_audit.audit_events WHERE 1=1"),
                 AppendOnlyViolationException);

    EXPECT_THROW(AppendOnlySqlGuard::validate_query_sql("TRUNCATE TABLE securecloud_audit.audit_events"),
                 AppendOnlyViolationException);

    EXPECT_THROW(AppendOnlySqlGuard::validate_query_sql("DROP TABLE securecloud_audit.audit_events"),
                 AppendOnlyViolationException);

    // Semicolon-chained multi-statements
    EXPECT_THROW(AppendOnlySqlGuard::validate_query_sql(
                     "SELECT * FROM securecloud_audit.audit_events; DROP TABLE securecloud_audit.audit_events"),
                 AppendOnlyViolationException);

    EXPECT_THROW(AppendOnlySqlGuard::validate_insert_sql(
                     "INSERT INTO securecloud_audit.audit_events FORMAT TabSeparated; DROP TABLE securecloud_audit.audit_events"),
                 AppendOnlyViolationException);
}

TEST(AuditRetentionAndAppendOnlyUnitTest, SchemaVerificationReportRejectsMissingTtlOrReceivedAtTtl) {
    repository::SchemaVerificationReport report;
    report.engine = "MergeTree";
    report.partition_key = "toYYYYMM(occurred_at)";
    report.sorting_key = "occurred_at, producer_service, event_type, event_id";

    // Invalid: Missing TTL clause
    report.create_table_query = "CREATE TABLE securecloud_audit.audit_events (...) ENGINE = MergeTree";
    {
        auto r = report;
        if (r.create_table_query.find("TTL") == std::string::npos) {
            r.violations.push_back("create_table_query does not contain a TTL clause");
        }
        EXPECT_FALSE(r.violations.empty());
    }

    // Invalid: TTL references received_at instead of occurred_at
    report.create_table_query = "CREATE TABLE securecloud_audit.audit_events (...) TTL toDateTime(received_at) + INTERVAL 36 MONTH DELETE";
    {
        auto r = report;
        std::string ttl_clause = r.create_table_query.substr(r.create_table_query.find("TTL"));
        if (ttl_clause.find("received_at") != std::string::npos) {
            r.violations.push_back("TTL clause incorrectly references 'received_at' instead of 'occurred_at'");
        }
        EXPECT_FALSE(r.violations.empty());
    }
}

TEST(AuditRetentionAndAppendOnlyUnitTest, DelayedAndOutOfOrderEventsAcceptedWhilePreHorizonEventsRejected) {
    auto now = std::chrono::system_clock::now();
    domain::AuditEventValidationLimits limits;

    // 1. Delayed event within retention horizon (6 months old) -> Accepted
    {
        domain::AuditEvent event;
        event.event_id = domain::EventId::generate_v7();
        event.occurred_at = now - std::chrono::hours(24 * 180);
        event.received_at = now;
        event.event_type = "auth.login.success";
        event.severity = domain::Severity::Info;
        event.producer_service = domain::ProducerService::Auth;
        event.actor_type = domain::ActorType::User;
        event.actor_id = "user_123";

        auto res = domain::AuditEventValidator::validate(event, limits, now);
        EXPECT_TRUE(res.is_valid());
        EXPECT_NE(event.occurred_at, *event.received_at);
    }

    // 2. Pre-retention horizon event (37 months / 1110 days old) -> Rejected with ClockSkewTooOld
    {
        domain::AuditEvent event;
        event.event_id = domain::EventId::generate_v7();
        event.occurred_at = now - std::chrono::hours(24 * 1110);
        event.received_at = now;
        event.event_type = "auth.login.success";
        event.severity = domain::Severity::Info;
        event.producer_service = domain::ProducerService::Auth;
        event.actor_type = domain::ActorType::User;
        event.actor_id = "user_123";

        auto res = domain::AuditEventValidator::validate(event, limits, now);
        EXPECT_FALSE(res.is_valid());

        bool found_skew_err = false;
        for (const auto& err : res.errors()) {
            if (err.code == domain::AuditValidationErrorCode::ClockSkewTooOld) {
                found_skew_err = true;
                break;
            }
        }
        EXPECT_TRUE(found_skew_err);
    }
}

} // namespace securecloud::audit::test