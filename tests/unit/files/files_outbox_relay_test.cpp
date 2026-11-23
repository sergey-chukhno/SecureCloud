#include "files/audit/audit_client_interface.hpp"
#include "files/audit/files_outbox_relay.hpp"
#include "files/repository/files_outbox_repository.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace securecloud::files::audit {
namespace {

using ::testing::_;
using ::testing::Return;
using ::testing::Throw;

[[nodiscard]] std::string make_uuid_v7() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    const auto now_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());

    std::array<uint8_t, 16> bytes{};
    bytes[0] = static_cast<uint8_t>((now_ms >> 40) & 0xFFu);
    bytes[1] = static_cast<uint8_t>((now_ms >> 32) & 0xFFu);
    bytes[2] = static_cast<uint8_t>((now_ms >> 24) & 0xFFu);
    bytes[3] = static_cast<uint8_t>((now_ms >> 16) & 0xFFu);
    bytes[4] = static_cast<uint8_t>((now_ms >> 8) & 0xFFu);
    bytes[5] = static_cast<uint8_t>(now_ms & 0xFFu);

    const uint64_t r1 = rng();
    const uint64_t r2 = rng();
    bytes[6] = static_cast<uint8_t>(0x70u | ((r1 >> 56) & 0x0Fu));
    bytes[7] = static_cast<uint8_t>((r1 >> 48) & 0xFFu);
    bytes[8] = static_cast<uint8_t>(0x80u | ((r2 >> 56) & 0x3Fu));
    bytes[9] = static_cast<uint8_t>((r2 >> 48) & 0xFFu);
    bytes[10] = static_cast<uint8_t>((r2 >> 40) & 0xFFu);
    bytes[11] = static_cast<uint8_t>((r2 >> 32) & 0xFFu);
    bytes[12] = static_cast<uint8_t>((r2 >> 24) & 0xFFu);
    bytes[13] = static_cast<uint8_t>((r2 >> 16) & 0xFFu);
    bytes[14] = static_cast<uint8_t>((r2 >> 8) & 0xFFu);
    bytes[15] = static_cast<uint8_t>(r2 & 0xFFu);

    char buf[37]{};
    std::snprintf(buf, sizeof(buf), "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", bytes[0],
                  bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10],
                  bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    return std::string(buf);
}

class MockAuditClient : public IFilesAuditClient {
  public:
    MOCK_METHOD(FilesAuditBatchSubmitResult, submit_batch,
                (const std::vector<securecloud::audit::v1::AuditEventProto>&), (override));
};

class FakeOutboxRepository final : public IFilesOutboxRepository {
  public:
    struct RecordedStateChange {
        std::string event_id;
        std::string reason;
    };

    std::vector<FilesOutboxEntity> pending_events;
    std::vector<std::string> published_ids;
    std::vector<RecordedStateChange> transient_failures;
    std::vector<RecordedStateChange> quarantined_events;
    size_t purge_return_value{0};
    size_t purge_calls{0};
    std::chrono::seconds last_lease_duration{0};

    void stage_event(const FilesOutboxEntity& event, pqxx::work&) override { pending_events.push_back(event); }

    void stage_event(const FilesOutboxEntity& event) override { pending_events.push_back(event); }

    std::vector<FilesOutboxEntity> fetch_and_lease_pending_batch(size_t limit,
                                                                 std::chrono::seconds lease_duration) override {
        last_lease_duration = lease_duration;
        std::vector<FilesOutboxEntity> res;
        const size_t n = std::min(limit, pending_events.size());
        res.reserve(n);
        for (size_t i = 0; i < n; ++i) {
            res.push_back(pending_events[i]);
        }
        pending_events.erase(pending_events.begin(), pending_events.begin() + static_cast<std::ptrdiff_t>(n));
        return res;
    }

    std::vector<FilesOutboxEntity> fetch_pending_events(size_t limit) override {
        return fetch_and_lease_pending_batch(limit, std::chrono::seconds{30});
    }

    bool mark_published(const std::string& event_id) override {
        published_ids.push_back(event_id);
        return true;
    }

    bool record_transient_failure(const std::string& event_id, std::string_view sanitized_error) override {
        transient_failures.push_back({event_id, std::string(sanitized_error)});
        return true;
    }

    bool mark_quarantined(const std::string& event_id, std::string_view sanitized_reason) override {
        quarantined_events.push_back({event_id, std::string(sanitized_reason)});
        return true;
    }

    size_t purge_published_older_than(std::chrono::system_clock::time_point, size_t) override {
        ++purge_calls;
        return purge_return_value;
    }

    size_t count_pending() override { return pending_events.size(); }

    double oldest_pending_age_seconds() override { return 0.0; }

    std::optional<FilesOutboxEntity> find_by_id(const std::string&) override { return std::nullopt; }
};

FilesOutboxEntity make_test_outbox_entity(std::string event_id, std::string aggregate_id, std::string event_type) {
    FilesOutboxEntity e;
    e.event_id = std::move(event_id);
    e.aggregate_type = "FILE";
    e.aggregate_id = std::move(aggregate_id);
    e.event_type = std::move(event_type);
    e.created_at = std::chrono::system_clock::now();
    e.payload_json = "{\"owner_user_id\":\"" + make_uuid_v7() + "\",\"file_size\":2048}";
    return e;
}

} // namespace

TEST(FilesOutboxRelayTest, PollAndDispatchPublishesCanonicalBatchSuccessfully) {
    const auto id1 = make_uuid_v7();
    const auto id2 = make_uuid_v7();
    const auto file_id = make_uuid_v7();

    auto repo = std::make_shared<FakeOutboxRepository>();
    repo->pending_events.push_back(make_test_outbox_entity(id1, file_id, "FILE_CREATED"));
    repo->pending_events.push_back(make_test_outbox_entity(id2, file_id, "FILE_FINALIZED"));

    auto client = std::make_shared<MockAuditClient>();
    EXPECT_CALL(*client, submit_batch(_))
        .WillOnce([&](const std::vector<securecloud::audit::v1::AuditEventProto>& batch) {
            EXPECT_EQ(batch.size(), 2u);
            EXPECT_EQ(batch[0].event_id(), id1);
            EXPECT_EQ(batch[0].event_type(), "file.created");
            EXPECT_EQ(batch[0].producer_service(), securecloud::audit::v1::PRODUCER_SERVICE_FILES);
            EXPECT_EQ(batch[0].producer_instance(), "files-test-1");
            EXPECT_EQ(batch[1].event_id(), id2);
            EXPECT_EQ(batch[1].event_type(), "file.upload.completed");

            FilesAuditBatchSubmitResult res;
            res.rpc_success = true;
            res.status = grpc::Status::OK;
            res.accepted_count = 2;
            res.rejected_count = 0;
            return res;
        });

    FilesOutboxMetrics metrics;
    FilesOutboxDiagnostics diag;
    FilesOutboxRelay relay(repo, client, {}, "files-test-1", &metrics, &diag);
    const size_t processed = relay.poll_and_dispatch(50);

    EXPECT_EQ(processed, 2u);
    EXPECT_EQ(repo->last_lease_duration, std::chrono::seconds(30));
    ASSERT_EQ(repo->published_ids.size(), 2u);
    EXPECT_EQ(repo->published_ids[0], id1);
    EXPECT_EQ(repo->published_ids[1], id2);
    EXPECT_TRUE(repo->transient_failures.empty());
    EXPECT_TRUE(repo->quarantined_events.empty());
    EXPECT_EQ(metrics.batches_dispatched.load(), 1u);
    EXPECT_EQ(metrics.events_published.load(), 2u);
    EXPECT_EQ(diag.consecutive_failures, 0u);
}

TEST(FilesOutboxRelayTest, PollAndDispatchRecordsTransientFailureOnRpcFailureOrException) {
    const auto id1 = make_uuid_v7();
    const auto id2 = make_uuid_v7();
    const auto file_id = make_uuid_v7();

    auto repo = std::make_shared<FakeOutboxRepository>();
    repo->pending_events.push_back(make_test_outbox_entity(id1, file_id, "FILE_CREATED"));
    repo->pending_events.push_back(make_test_outbox_entity(id2, file_id, "FILE_DELETED"));

    auto client = std::make_shared<MockAuditClient>();
    FilesAuditBatchSubmitResult rpc_fail;
    rpc_fail.rpc_success = false;
    rpc_fail.status = grpc::Status(grpc::StatusCode::UNAVAILABLE, "Audit service unavailable");

    EXPECT_CALL(*client, submit_batch(_)).WillOnce(Return(rpc_fail));

    FilesOutboxMetrics metrics;
    FilesOutboxDiagnostics diag;
    FilesOutboxRelay relay(repo, client, {}, "files-1", &metrics, &diag);
    const size_t processed = relay.poll_and_dispatch(50);

    EXPECT_EQ(processed, 2u);
    EXPECT_TRUE(repo->published_ids.empty());
    EXPECT_TRUE(repo->quarantined_events.empty());
    ASSERT_EQ(repo->transient_failures.size(), 2u);
    EXPECT_EQ(repo->transient_failures[0].event_id, id1);
    EXPECT_EQ(repo->transient_failures[0].reason, "Audit service unavailable");
    EXPECT_EQ(repo->transient_failures[1].event_id, id2);
    EXPECT_EQ(metrics.transient_failures.load(), 2u);
    EXPECT_EQ(diag.consecutive_failures, 1u);

    const auto id3 = make_uuid_v7();
    repo->transient_failures.clear();
    repo->pending_events.push_back(make_test_outbox_entity(id3, file_id, "FILE_CREATED"));
    EXPECT_CALL(*client, submit_batch(_)).WillOnce(Throw(std::runtime_error("transport_reset")));

    EXPECT_EQ(relay.poll_and_dispatch(50), 1u);
    ASSERT_EQ(repo->transient_failures.size(), 1u);
    EXPECT_EQ(repo->transient_failures[0].event_id, id3);
    EXPECT_EQ(repo->transient_failures[0].reason, "transport_reset");
    EXPECT_EQ(diag.consecutive_failures, 2u);
}

TEST(FilesOutboxRelayTest, QuarantinesPerEventRejectedIdsWhilePublishingAcceptedEvents) {
    const auto id_ok_1 = make_uuid_v7();
    const auto id_rejected = make_uuid_v7();
    const auto id_ok_2 = make_uuid_v7();
    const auto file_id = make_uuid_v7();

    auto repo = std::make_shared<FakeOutboxRepository>();
    repo->pending_events.push_back(make_test_outbox_entity(id_ok_1, file_id, "file.created"));
    repo->pending_events.push_back(make_test_outbox_entity(id_rejected, file_id, "file.metadata.updated"));
    repo->pending_events.push_back(make_test_outbox_entity(id_ok_2, file_id, "file.downloaded"));

    auto client = std::make_shared<MockAuditClient>();
    EXPECT_CALL(*client, submit_batch(_))
        .WillOnce([&](const std::vector<securecloud::audit::v1::AuditEventProto>& batch) {
            EXPECT_EQ(batch.size(), 3u);
            FilesAuditBatchSubmitResult res;
            res.rpc_success = true;
            res.status = grpc::Status::OK;
            res.accepted_count = 2;
            res.rejected_count = 1;
            res.rejected_event_ids = {id_rejected};
            return res;
        });

    FilesOutboxRelay relay(repo, client);
    const size_t processed = relay.poll_and_dispatch(50);

    EXPECT_EQ(processed, 3u);
    ASSERT_EQ(repo->published_ids.size(), 2u);
    EXPECT_EQ(repo->published_ids[0], id_ok_1);
    EXPECT_EQ(repo->published_ids[1], id_ok_2);
    ASSERT_EQ(repo->quarantined_events.size(), 1u);
    EXPECT_EQ(repo->quarantined_events[0].event_id, id_rejected);
    EXPECT_EQ(repo->quarantined_events[0].reason, "audit_service_rejected");
    EXPECT_TRUE(repo->transient_failures.empty());
}

TEST(FilesOutboxRelayTest, QuarantinesCorruptedRowsLocallyBeforeGrpcDispatch) {
    const auto valid_id = make_uuid_v7();
    const auto file_id = make_uuid_v7();

    auto repo = std::make_shared<FakeOutboxRepository>();
    repo->pending_events.push_back(make_test_outbox_entity("corrupted-non-uuid", file_id, "FILE_CREATED"));
    repo->pending_events.push_back(make_test_outbox_entity(valid_id, file_id, "FILE_CREATED"));

    auto client = std::make_shared<MockAuditClient>();
    EXPECT_CALL(*client, submit_batch(_))
        .WillOnce([&](const std::vector<securecloud::audit::v1::AuditEventProto>& batch) {
            EXPECT_EQ(batch.size(), 1u);
            EXPECT_EQ(batch[0].event_id(), valid_id);
            FilesAuditBatchSubmitResult res;
            res.rpc_success = true;
            res.status = grpc::Status::OK;
            res.accepted_count = 1;
            res.rejected_count = 0;
            return res;
        });

    FilesOutboxRelay relay(repo, client);
    const size_t processed = relay.poll_and_dispatch(50);

    EXPECT_EQ(processed, 2u);
    ASSERT_EQ(repo->quarantined_events.size(), 1u);
    EXPECT_EQ(repo->quarantined_events[0].event_id, "corrupted-non-uuid");
    EXPECT_NE(repo->quarantined_events[0].reason.find("local_validation_failed:"), std::string::npos);
    ASSERT_EQ(repo->published_ids.size(), 1u);
    EXPECT_EQ(repo->published_ids[0], valid_id);
}

TEST(FilesOutboxRelayTest, ProbesAndIsolatesInvalidArgumentBatchWithoutDroppingHealthySiblings) {
    const auto id_good = make_uuid_v7();
    const auto id_bad = make_uuid_v7();
    const auto file_id = make_uuid_v7();

    auto repo = std::make_shared<FakeOutboxRepository>();
    repo->pending_events.push_back(make_test_outbox_entity(id_good, file_id, "file.created"));
    repo->pending_events.push_back(make_test_outbox_entity(id_bad, file_id, "file.deleted"));

    auto client = std::make_shared<MockAuditClient>();
    EXPECT_CALL(*client, submit_batch(_))
        .WillOnce([](const std::vector<securecloud::audit::v1::AuditEventProto>& batch) {
            EXPECT_EQ(batch.size(), 2u);
            FilesAuditBatchSubmitResult res;
            res.rpc_success = false;
            res.status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "bad event");
            return res;
        })
        .WillOnce([&](const std::vector<securecloud::audit::v1::AuditEventProto>& batch) {
            EXPECT_EQ(batch.size(), 1u);
            EXPECT_EQ(batch[0].event_id(), id_good);
            FilesAuditBatchSubmitResult res;
            res.rpc_success = true;
            res.status = grpc::Status::OK;
            res.accepted_count = 1;
            return res;
        })
        .WillOnce([&](const std::vector<securecloud::audit::v1::AuditEventProto>& batch) {
            EXPECT_EQ(batch.size(), 1u);
            EXPECT_EQ(batch[0].event_id(), id_bad);
            FilesAuditBatchSubmitResult res;
            res.rpc_success = false;
            res.status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "bad schema");
            return res;
        });

    FilesOutboxRelay relay(repo, client);
    const size_t processed = relay.poll_and_dispatch(50);

    EXPECT_EQ(processed, 2u);
    ASSERT_EQ(repo->published_ids.size(), 1u);
    EXPECT_EQ(repo->published_ids[0], id_good);
    ASSERT_EQ(repo->quarantined_events.size(), 1u);
    EXPECT_EQ(repo->quarantined_events[0].event_id, id_bad);
    EXPECT_TRUE(repo->transient_failures.empty());
}

TEST(FilesOutboxRelayTest, RetainsEventsAsPendingOnPermissionDeniedSecurityFault) {
    const auto id1 = make_uuid_v7();
    const auto file_id = make_uuid_v7();

    auto repo = std::make_shared<FakeOutboxRepository>();
    repo->pending_events.push_back(make_test_outbox_entity(id1, file_id, "file.created"));

    auto client = std::make_shared<MockAuditClient>();
    FilesAuditBatchSubmitResult auth_fail;
    auth_fail.rpc_success = false;
    auth_fail.status = grpc::Status(grpc::StatusCode::PERMISSION_DENIED, "mTLS SAN mismatch");
    EXPECT_CALL(*client, submit_batch(_)).WillOnce(Return(auth_fail));

    FilesOutboxMetrics metrics;
    FilesOutboxRelay relay(repo, client, {}, "files-1", &metrics, nullptr);
    EXPECT_EQ(relay.poll_and_dispatch(50), 1u);

    EXPECT_TRUE(repo->published_ids.empty());
    EXPECT_TRUE(repo->quarantined_events.empty());
    ASSERT_EQ(repo->transient_failures.size(), 1u);
    EXPECT_EQ(metrics.security_auth_failures.load(), 1u);
}

TEST(FilesOutboxRelayTest, ClampsLeaseBatchSizeToGrpcMaxBatchSize100) {
    const auto file_id = make_uuid_v7();
    auto repo = std::make_shared<FakeOutboxRepository>();
    for (int i = 0; i < 125; ++i) {
        repo->pending_events.push_back(make_test_outbox_entity(make_uuid_v7(), file_id, "file.chunk.uploaded"));
    }

    auto client = std::make_shared<MockAuditClient>();
    EXPECT_CALL(*client, submit_batch(_))
        .WillOnce([](const std::vector<securecloud::audit::v1::AuditEventProto>& batch) {
            EXPECT_EQ(batch.size(), 100u);
            FilesAuditBatchSubmitResult res;
            res.rpc_success = true;
            res.status = grpc::Status::OK;
            res.accepted_count = 100;
            return res;
        })
        .WillOnce([](const std::vector<securecloud::audit::v1::AuditEventProto>& batch) {
            EXPECT_EQ(batch.size(), 25u);
            FilesAuditBatchSubmitResult res;
            res.rpc_success = true;
            res.status = grpc::Status::OK;
            res.accepted_count = 25;
            return res;
        });

    FilesOutboxRelay relay(repo, client);
    EXPECT_EQ(relay.poll_and_dispatch(150), 100u);
    EXPECT_EQ(relay.poll_and_dispatch(150), 25u);
    EXPECT_EQ(repo->published_ids.size(), 125u);
}

TEST(FilesOutboxRelayTest, ComputesBoundedExponentialBackoffWithJitter) {
    auto repo = std::make_shared<FakeOutboxRepository>();
    auto client = std::make_shared<MockAuditClient>();

    FilesOutboxRelayConfig cfg;
    cfg.initial_backoff = std::chrono::milliseconds(200);
    cfg.max_backoff = std::chrono::milliseconds(5000);
    cfg.backoff_multiplier = 2.0;
    cfg.jitter_ratio = 0.25;

    FilesOutboxRelay relay(repo, client, cfg);
    EXPECT_EQ(relay.compute_backoff_delay(0).count(), 0);

    for (int i = 0; i < 20; ++i) {
        const auto d1 = relay.compute_backoff_delay(1).count();
        EXPECT_GE(d1, 150);
        EXPECT_LE(d1, 250);

        const auto d2 = relay.compute_backoff_delay(2).count();
        EXPECT_GE(d2, 300);
        EXPECT_LE(d2, 500);

        const auto d10 = relay.compute_backoff_delay(10).count();
        EXPECT_GE(d10, 3750);
        EXPECT_LE(d10, 5000);
    }
}

TEST(FilesOutboxRelayTest, PurgesOldPublishedRecords) {
    auto repo = std::make_shared<FakeOutboxRepository>();
    repo->purge_return_value = 42;
    auto client = std::make_shared<MockAuditClient>();

    FilesOutboxMetrics metrics;
    FilesOutboxRelay relay(repo, client, {}, "files-1", &metrics, nullptr);
    EXPECT_EQ(relay.purge_old_published_records(), 42u);
    EXPECT_EQ(repo->purge_calls, 1u);
    EXPECT_EQ(metrics.rows_purged.load(), 42u);
}

TEST(FilesOutboxRelayTest, EmptyOutboxReturnsZero) {
    auto repo = std::make_shared<FakeOutboxRepository>();
    auto client = std::make_shared<MockAuditClient>();
    EXPECT_CALL(*client, submit_batch(_)).Times(0);

    FilesOutboxRelay relay(repo, client);
    const size_t processed = relay.poll_and_dispatch(10);
    EXPECT_EQ(processed, 0u);
}

TEST(FilesOutboxRelayTest, LifecycleStartStopAndShutdownDrain) {
    const auto id1 = make_uuid_v7();
    const auto file_id = make_uuid_v7();

    auto repo = std::make_shared<FakeOutboxRepository>();
    auto client = std::make_shared<MockAuditClient>();

    EXPECT_CALL(*client, submit_batch(_))
        .WillRepeatedly([](const std::vector<securecloud::audit::v1::AuditEventProto>& batch) {
            FilesAuditBatchSubmitResult res;
            res.rpc_success = true;
            res.status = grpc::Status::OK;
            res.accepted_count = static_cast<uint32_t>(batch.size());
            return res;
        });

    FilesOutboxRelayConfig cfg;
    cfg.poll_interval = std::chrono::milliseconds(50);
    cfg.shutdown_drain_timeout = std::chrono::milliseconds(500);
    FilesOutboxRelay relay(repo, client, cfg);

    EXPECT_FALSE(relay.is_running());
    relay.start();
    EXPECT_TRUE(relay.is_running());

    repo->pending_events.push_back(make_test_outbox_entity(id1, file_id, "file.created"));
    relay.notify();

    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    relay.stop();
    EXPECT_FALSE(relay.is_running());
    ASSERT_EQ(repo->published_ids.size(), 1u);
    EXPECT_EQ(repo->published_ids[0], id1);
}

} // namespace securecloud::files::audit

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
#ifdef _WIN32
    std::fflush(nullptr);
    ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(result));
#else
    return result;
#endif
}
