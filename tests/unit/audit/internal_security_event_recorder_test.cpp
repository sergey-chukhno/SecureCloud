#include "repository/audit_event_repository_interface.hpp"
#include "security/internal_security_event_recorder.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace securecloud::audit::security::testing {

class MockAuditEventRepository : public repository::IAuditEventRepository {
  public:
    MOCK_METHOD(bool, insert_batch, (const std::vector<domain::AuditEvent>& events), (override));
    MOCK_METHOD(repository::RepositoryBatchWriteResult, insert_batch_classified,
                (const std::vector<domain::AuditEvent>& events), (override));
    MOCK_METHOD(std::vector<domain::AuditEvent>, query_by_time_range,
                (std::chrono::system_clock::time_point start, std::chrono::system_clock::time_point end,
                 uint32_t limit),
                (override));
    MOCK_METHOD(std::vector<domain::AuditEvent>, query_by_producer,
                (const std::string& producer_service, std::chrono::system_clock::time_point start,
                 std::chrono::system_clock::time_point end, uint32_t limit),
                (override));
    MOCK_METHOD(std::vector<domain::AuditEvent>, query_by_correlation_id,
                (const std::string& correlation_id, uint32_t limit), (override));
    MOCK_METHOD(std::optional<domain::AuditEvent>, find_by_event_id, (const domain::EventId& event_id), (override));
};

class InternalSecurityEventRecorderTest : public ::testing::Test {
  protected:
    void SetUp() override {
        reset_recursion_prevented_count();
        mock_repo_ = std::make_shared<MockAuditEventRepository>();
        ingestion_service_ = std::make_shared<service::AuditIngestionService>(mock_repo_);
        recorder_ = std::make_unique<InternalSecurityEventRecorder>(ingestion_service_, "audit-node-01");
    }

    std::shared_ptr<MockAuditEventRepository> mock_repo_;
    std::shared_ptr<service::AuditIngestionService> ingestion_service_;
    std::unique_ptr<InternalSecurityEventRecorder> recorder_;
};

TEST_F(InternalSecurityEventRecorderTest, SuccessfulEventRecording) {
    EXPECT_CALL(*mock_repo_, insert_batch_classified(::testing::_))
        .WillOnce(::testing::Return(repository::RepositoryBatchWriteResult{
            .status = repository::RepositoryWriteStatus::Committed, .error_code = "", .sanitized_reason = ""}));

    SecurityEventContext ctx;
    ctx.verified_peer_identity = "auth.securecloud.internal";
    ctx.rpc_method = "SubmitAuditEvent";

    bool success = recorder_->record_event(InternalSecurityEventType::SensitiveDataDetected, ctx);

    EXPECT_TRUE(success);
    EXPECT_EQ(recorder_->events_recorded_count(), 1);
    EXPECT_EQ(recorder_->events_dropped_count(), 0);
    EXPECT_EQ(recorder_->recursion_prevented_count(), 0);
}

TEST_F(InternalSecurityEventRecorderTest, DroppedEventOnRepositoryFailure) {
    EXPECT_CALL(*mock_repo_, insert_batch_classified(::testing::_))
        .WillOnce(::testing::Return(
            repository::RepositoryBatchWriteResult{.status = repository::RepositoryWriteStatus::DeterministicFailure,
                                                   .error_code = "CONNECTION_ERROR",
                                                   .sanitized_reason = "ClickHouse unavailable"}));

    SecurityEventContext ctx;
    ctx.peer_socket_address = "10.0.0.5:50055";

    bool success = recorder_->record_event(InternalSecurityEventType::UnauthenticatedConnection, ctx);

    EXPECT_FALSE(success);
    EXPECT_EQ(recorder_->events_recorded_count(), 0);
    EXPECT_EQ(recorder_->events_dropped_count(), 1);
}

TEST_F(InternalSecurityEventRecorderTest, AntiRecursionGuardDropsReentrantRecordings) {
    EXPECT_CALL(*mock_repo_, insert_batch_classified(::testing::_))
        .WillOnce(::testing::Invoke([this](const std::vector<domain::AuditEvent>&) {
            // Re-entrant call inside repository execution
            SecurityEventContext inner_ctx;
            bool inner_res = recorder_->record_event(InternalSecurityEventType::IngestionQueueSaturated, inner_ctx);
            EXPECT_FALSE(inner_res);

            return repository::RepositoryBatchWriteResult{
                .status = repository::RepositoryWriteStatus::Committed, .error_code = "", .sanitized_reason = ""};
        }));

    SecurityEventContext ctx;
    bool outer_res = recorder_->record_event(InternalSecurityEventType::ServiceStarted, ctx);

    EXPECT_TRUE(outer_res);
    EXPECT_EQ(recorder_->events_recorded_count(), 1);
    EXPECT_EQ(recorder_->events_dropped_count(), 1);
    EXPECT_EQ(recorder_->recursion_prevented_count(), 1);
}

TEST_F(InternalSecurityEventRecorderTest, NullIngestionServiceHandledSafely) {
    InternalSecurityEventRecorder null_recorder(nullptr, "audit-node-01");
    SecurityEventContext ctx;

    bool success = null_recorder.record_event(InternalSecurityEventType::ServiceStarted, ctx);

    EXPECT_FALSE(success);
    EXPECT_EQ(null_recorder.events_dropped_count(), 1);
}

} // namespace securecloud::audit::security::testing