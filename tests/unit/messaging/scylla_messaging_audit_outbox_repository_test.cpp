#include "messaging/db/mock_scylla_session.hpp"
#include "messaging/repository/in_memory_messaging_audit_outbox_repository.hpp"
#include "messaging/repository/scylla_messaging_audit_outbox_repository.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::messaging::repository::test {
namespace {

using namespace std::chrono_literals;

AuditOutboxRecord make_sample_record(std::string event_id, std::chrono::system_clock::time_point created_at,
                                     int32_t shard_id = 3) {
    AuditOutboxRecord rec;
    rec.outbox_bucket = "2026111308";
    rec.shard_id = shard_id;
    rec.created_at = created_at;
    rec.event_id = std::move(event_id);
    rec.event_type = "message.submitted";
    rec.severity = "INFO";
    rec.actor_user_id = "user-101";
    rec.actor_device_id = "dev-202";
    rec.target_resource = "conversation:01930000-0000-7000-8000-000000000001";
    rec.payload_proto_bin = {0x08, 0x01, 0x12, 0x04, 0x74, 0x65, 0x73, 0x74};
    rec.publish_status = "PENDING";
    rec.attempt_count = 0;
    return rec;
}

TEST(ScyllaMessagingAuditOutboxRepositoryTest, PreparesAllRequiredStatementsAndEnqueuesWithLocalQuorum) {
    auto session = std::make_shared<db::MockScyllaSession>();
    ScyllaMessagingAuditOutboxRepository repo(session);

    const auto prepared = session->get_prepared_statements();
    EXPECT_TRUE(prepared.contains("audit_outbox_enqueue"));
    EXPECT_TRUE(prepared.contains("audit_outbox_fetch_pending"));
    EXPECT_TRUE(prepared.contains("audit_outbox_lease_event"));
    EXPECT_TRUE(prepared.contains("audit_outbox_mark_published"));
    EXPECT_TRUE(prepared.contains("audit_outbox_select_attempts"));
    EXPECT_TRUE(prepared.contains("audit_outbox_record_failure"));
    EXPECT_TRUE(prepared.contains("audit_outbox_count_pending"));

    const auto base_time = std::chrono::system_clock::time_point(std::chrono::milliseconds(1763020800000LL));
    const auto rec = make_sample_record("01930000-0000-7000-8000-000000000010", base_time, 5);

    ASSERT_NO_THROW(repo.enqueue_audit_event(rec));

    const auto executed = session->get_executed_prepared();
    ASSERT_EQ(executed.size(), 1U);
    EXPECT_EQ(executed[0].first, db::PreparedStatementId{"audit_outbox_enqueue"});
}

TEST(ScyllaMessagingAuditOutboxRepositoryTest, FetchPendingAppliesWorkerLeasesAndSkipsActiveLeases) {
    auto session = std::make_shared<db::MockScyllaSession>();

    auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(1763020850000LL));
    ScyllaMessagingAuditOutboxRepository repo(session, [&now]() { return now; });

    const int64_t t1_ms = 1763020810000LL;
    const int64_t t2_ms = 1763020820000LL;
    const int64_t active_lease_ms = 1763020880000LL; // now + 30s (still leased)

    const std::vector<std::string> cols = {"outbox_bucket",   "shard_id",        "created_at",      "event_id",
                                           "event_type",      "severity",        "actor_user_id",   "actor_device_id",
                                           "target_resource", "payload_proto_bin", "publish_status",  "attempt_count",
                                           "last_attempt_at", "last_error",      "leased_until"};

    db::ScyllaRow row_unleased(
        cols, {"2026111308", int32_t{4}, t1_ms, "01930000-0000-7000-8000-000000000021", "message.submitted", "INFO",
               "user-1", "dev-1", "conv-1", std::vector<uint8_t>{0x01, 0x02}, "PENDING", int32_t{0},
               db::ScyllaValue::null(), db::ScyllaValue::null(), db::ScyllaValue::null()});

    db::ScyllaRow row_leased(
        cols, {"2026111308", int32_t{4}, t2_ms, "01930000-0000-7000-8000-000000000022", "message.delivered", "INFO",
               "user-1", "dev-2", "conv-1", std::vector<uint8_t>{0x03, 0x04}, "PENDING", int32_t{1},
               db::ScyllaValue::null(), db::ScyllaValue::null(), active_lease_ms});

    session->set_prepared_result(db::PreparedStatementId{"audit_outbox_fetch_pending"},
                                 db::ScyllaQueryResult({row_unleased, row_leased}));

    const auto claimed = repo.fetch_pending_events("2026111308", 4, 10, 30s);
    ASSERT_EQ(claimed.size(), 1U);
    EXPECT_EQ(claimed[0].event_id, "01930000-0000-7000-8000-000000000021");
    EXPECT_EQ(claimed[0].leased_until, now + 30s);

    const auto executed = session->get_executed_prepared();
    ASSERT_EQ(executed.size(), 2U);
    EXPECT_EQ(executed[0].first, db::PreparedStatementId{"audit_outbox_fetch_pending"});
    EXPECT_EQ(executed[1].first, db::PreparedStatementId{"audit_outbox_lease_event"});
}

TEST(ScyllaMessagingAuditOutboxRepositoryTest, MarkPublishedRecordFailureAndCountBacklog) {
    auto session = std::make_shared<db::MockScyllaSession>();
    auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(1763020900000LL));
    ScyllaMessagingAuditOutboxRepository repo(session, [&now]() { return now; });

    const auto created_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(1763020810000LL));

    repo.mark_published("2026111308", 2, created_at, "01930000-0000-7000-8000-000000000031");

    session->set_prepared_result(
        db::PreparedStatementId{"audit_outbox_select_attempts"},
        db::ScyllaQueryResult({db::ScyllaRow({"attempt_count"}, {int32_t{4}})}));

    repo.record_failure("2026111308", 2, created_at, "01930000-0000-7000-8000-000000000032",
                        "gRPC UNAVAILABLE ciphertext=secret_leak", true);

    session->set_prepared_result(
        db::PreparedStatementId{"audit_outbox_count_pending"},
        db::ScyllaQueryResult({db::ScyllaRow({"pending_count"}, {int64_t{17}})}));

    EXPECT_EQ(repo.count_pending_backlog("2026111308", 2), 17U);

    const auto executed = session->get_executed_prepared();
    ASSERT_EQ(executed.size(), 4U);
    EXPECT_EQ(executed[0].first, db::PreparedStatementId{"audit_outbox_mark_published"});
    EXPECT_EQ(executed[1].first, db::PreparedStatementId{"audit_outbox_select_attempts"});
    EXPECT_EQ(executed[2].first, db::PreparedStatementId{"audit_outbox_record_failure"});
    EXPECT_EQ(executed[3].first, db::PreparedStatementId{"audit_outbox_count_pending"});
}

TEST(InMemoryMessagingAuditOutboxRepositoryTest, EndToEndLifecycleLeasingFailureAndQuarantine) {
    auto now = std::chrono::system_clock::time_point(std::chrono::milliseconds(1763020800000LL));
    InMemoryMessagingAuditOutboxRepository repo([&now]() { return now; });

    const auto t1 = now + 1s;
    const auto t2 = now + 2s;
    const auto rec1 = make_sample_record("01930000-0000-7000-8000-000000000041", t1, 7);
    const auto rec2 = make_sample_record("01930000-0000-7000-8000-000000000042", t2, 7);

    repo.enqueue_audit_event(rec1);
    repo.enqueue_audit_event(rec2);
    EXPECT_EQ(repo.count_pending_backlog("2026111308", 7), 2U);

    // Worker 1 claims batch of 1 with 30s lease
    const auto batch1 = repo.fetch_pending_events("2026111308", 7, 1, 30s);
    ASSERT_EQ(batch1.size(), 1U);
    EXPECT_EQ(batch1[0].event_id, rec1.event_id);

    // Concurrent Worker 2 immediately fetches 2 -> skips leased rec1, claims only rec2
    const auto batch2 = repo.fetch_pending_events("2026111308", 7, 2, 30s);
    ASSERT_EQ(batch2.size(), 1U);
    EXPECT_EQ(batch2[0].event_id, rec2.event_id);

    // Concurrent Worker 3 sees 0 available while both leases are active
    EXPECT_TRUE(repo.fetch_pending_events("2026111308", 7, 10, 30s).empty());

    // Mark rec1 as PUBLISHED -> drops from pending backlog
    repo.mark_published("2026111308", 7, t1, rec1.event_id);
    EXPECT_EQ(repo.count_pending_backlog("2026111308", 7), 1U);
    const auto stored1 = repo.find_record("2026111308", 7, t1, rec1.event_id);
    ASSERT_TRUE(stored1.has_value());
    EXPECT_EQ(stored1->publish_status, "PUBLISHED");

    // Advance clock past lease expiry (31s) -> rec2 becomes reclaimable
    now += 31s;
    const auto reclaimed = repo.fetch_pending_events("2026111308", 7, 5, 30s);
    ASSERT_EQ(reclaimed.size(), 1U);
    EXPECT_EQ(reclaimed[0].event_id, rec2.event_id);

    // Record transient failure (non-quarantine)
    repo.record_failure("2026111308", 7, t2, rec2.event_id, "Deadline exceeded", false);
    auto stored2 = repo.find_record("2026111308", 7, t2, rec2.event_id);
    ASSERT_TRUE(stored2.has_value());
    EXPECT_EQ(stored2->publish_status, "PENDING");
    EXPECT_EQ(stored2->attempt_count, 1);
    EXPECT_EQ(repo.count_pending_backlog("2026111308", 7), 1U);

    // Record terminal failure (quarantine)
    repo.record_failure("2026111308", 7, t2, rec2.event_id, "Max retries exhausted", true);
    stored2 = repo.find_record("2026111308", 7, t2, rec2.event_id);
    ASSERT_TRUE(stored2.has_value());
    EXPECT_EQ(stored2->publish_status, "QUARANTINED");
    EXPECT_EQ(stored2->attempt_count, 2);
    EXPECT_EQ(repo.count_pending_backlog("2026111308", 7), 0U);
}

} // namespace
} // namespace securecloud::messaging::repository::test
