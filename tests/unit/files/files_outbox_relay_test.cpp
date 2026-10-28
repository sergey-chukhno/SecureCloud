#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "files/audit/audit_client_interface.hpp"
#include "files/audit/files_outbox_relay.hpp"
#include "files/repository/files_outbox_repository.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::files::audit {
namespace {

using ::testing::_;
using ::testing::Return;

class MockAuditClient : public IFilesAuditClient {
  public:
    MOCK_METHOD(bool, submit_batch, (const std::vector<securecloud::audit::v1::AuditEventProto>&), (override));
};

class FakeOutboxRepository : public FilesOutboxRepository {
  public:
    FakeOutboxRepository() : FilesOutboxRepository(nullptr) {}

    std::vector<FilesOutboxEntity> pending_events;
    std::vector<std::string> published_ids;
    std::vector<std::string> failed_ids;

    std::vector<FilesOutboxEntity> fetch_pending_events(size_t limit) override {
        std::vector<FilesOutboxEntity> res;
        size_t n = std::min(limit, pending_events.size());
        for (size_t i = 0; i < n; ++i) {
            res.push_back(pending_events[i]);
        }
        pending_events.erase(pending_events.begin(), pending_events.begin() + n);
        return res;
    }

    bool mark_published(const std::string& event_id) override {
        published_ids.push_back(event_id);
        return true;
    }

    bool mark_failed(const std::string& event_id) override {
        failed_ids.push_back(event_id);
        return true;
    }
};

FilesOutboxEntity make_test_outbox_entity(std::string event_id, std::string aggregate_id, std::string event_type) {
    FilesOutboxEntity e;
    e.event_id = std::move(event_id);
    e.aggregate_id = std::move(aggregate_id);
    e.event_type = std::move(event_type);
    e.created_at = std::chrono::system_clock::now();
    e.payload_json = "{\"owner_user_id\":\"usr-test-1\",\"file_size\":2048}";
    return e;
}
} // namespace

TEST(FilesOutboxRelayTest, PollAndDispatchPublishesBatchSuccessfully) {
    auto repo = std::make_shared<FakeOutboxRepository>();
    repo->pending_events.push_back(make_test_outbox_entity("evt-1", "file-100", "FILE_CREATED"));
    repo->pending_events.push_back(make_test_outbox_entity("evt-2", "file-100", "FILE_FINALIZED"));

    auto client = std::make_shared<MockAuditClient>();
    EXPECT_CALL(*client, submit_batch(_))
        .WillOnce([](const std::vector<securecloud::audit::v1::AuditEventProto>& batch) {
            EXPECT_EQ(batch.size(), 2u);
            EXPECT_EQ(batch[0].event_id(), "evt-1");
            EXPECT_EQ(batch[0].event_type(), "FILE_CREATED");
            EXPECT_EQ(batch[0].producer_service(),
                      securecloud::audit::v1::ProducerServiceProto::PRODUCER_SERVICE_FILES);
            EXPECT_EQ(batch[1].event_id(), "evt-2");
            EXPECT_EQ(batch[1].event_type(), "FILE_FINALIZED");
            return true;
        });

    FilesOutboxRelay relay(repo, client);
    size_t processed = relay.poll_and_dispatch(50);

    EXPECT_EQ(processed, 2u);
    ASSERT_EQ(repo->published_ids.size(), 2u);
    EXPECT_EQ(repo->published_ids[0], "evt-1");
    EXPECT_EQ(repo->published_ids[1], "evt-2");
    EXPECT_TRUE(repo->failed_ids.empty());
}

TEST(FilesOutboxRelayTest, PollAndDispatchHandlesAuditSubmissionFailure) {
    auto repo = std::make_shared<FakeOutboxRepository>();
    repo->pending_events.push_back(make_test_outbox_entity("evt-fail-1", "file-200", "FILE_CREATED"));

    auto client = std::make_shared<MockAuditClient>();
    EXPECT_CALL(*client, submit_batch(_)).WillOnce(Return(false));

    FilesOutboxRelay relay(repo, client);
    size_t processed = relay.poll_and_dispatch(50);

    EXPECT_EQ(processed, 1u);
    EXPECT_TRUE(repo->published_ids.empty());
    ASSERT_EQ(repo->failed_ids.size(), 1u);
    EXPECT_EQ(repo->failed_ids[0], "evt-fail-1");
}

TEST(FilesOutboxRelayTest, EmptyOutboxReturnsZero) {
    auto repo = std::make_shared<FakeOutboxRepository>();
    auto client = std::make_shared<MockAuditClient>();
    EXPECT_CALL(*client, submit_batch(_)).Times(0);

    FilesOutboxRelay relay(repo, client);
    size_t processed = relay.poll_and_dispatch(10);
    EXPECT_EQ(processed, 0u);
}

TEST(FilesOutboxRelayTest, LifecycleStartStop) {
    auto repo = std::make_shared<FakeOutboxRepository>();
    auto client = std::make_shared<MockAuditClient>();

    FilesOutboxRelayConfig cfg;
    cfg.poll_interval_ms = std::chrono::milliseconds(50);
    FilesOutboxRelay relay(repo, client, cfg);

    EXPECT_FALSE(relay.is_running());
    relay.start();
    EXPECT_TRUE(relay.is_running());
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    relay.stop();
    EXPECT_FALSE(relay.is_running());
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
