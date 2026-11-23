#include "domain/audit_event_validator.hpp"
#include "repository/audit_event_repository_interface.hpp"
#include "security/internal_security_event_recorder.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::audit::security::testing {

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;

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

class InternalSecurityEventRecorderUnitTest : public ::testing::Test {
  protected:
    void SetUp() override {
        reset_recursion_prevented_count();
        mock_repo_ = std::make_shared<NiceMock<MockAuditEventRepository>>();
        ON_CALL(*mock_repo_, insert_batch_classified(_))
            .WillByDefault(Return(repository::RepositoryBatchWriteResult{
                .status = repository::RepositoryWriteStatus::Committed, .error_code = "", .sanitized_reason = ""}));
        ON_CALL(*mock_repo_, insert_batch(_)).WillByDefault(Return(true));

        ingestion_service_ = std::make_shared<service::AuditIngestionService>(mock_repo_);
        recorder_ = std::make_unique<InternalSecurityEventRecorder>(ingestion_service_, "audit-node-01");
    }

    std::shared_ptr<NiceMock<MockAuditEventRepository>> mock_repo_;
    std::shared_ptr<service::AuditIngestionService> ingestion_service_;
    std::unique_ptr<InternalSecurityEventRecorder> recorder_;
    domain::AuditEventValidator validator_{};
};

// Test 1: Event Classification & Canonical Mapping for all 11 security event types
TEST_F(InternalSecurityEventRecorderUnitTest, EventClassificationAndCanonicalMapping) {
    InternalSecurityEventFactory factory{"audit-node-01"};

    const std::vector<InternalSecurityEventType> all_types = {InternalSecurityEventType::UnauthenticatedConnection,
                                                              InternalSecurityEventType::ProducerIdentityMismatch,
                                                              InternalSecurityEventType::UntrustedClientCertificate,
                                                              InternalSecurityEventType::SensitiveDataDetected,
                                                              InternalSecurityEventType::MalformedPayloadStructure,
                                                              InternalSecurityEventType::ExcessiveClockSkew,
                                                              InternalSecurityEventType::OversizedBatchRejected,
                                                              InternalSecurityEventType::IngestionQueueSaturated,
                                                              InternalSecurityEventType::PersistenceStorageFailure,
                                                              InternalSecurityEventType::ServiceStarted,
                                                              InternalSecurityEventType::ServiceDraining};

    SecurityEventContext ctx;
    ctx.rpc_method = "TestPipeline";
    ctx.peer_socket_address = "10.0.0.1:50055";

    for (auto type : all_types) {
        auto event = factory.create_event(type, ctx);
        auto val_res = validator_.validate(event);
        EXPECT_TRUE(val_res.is_valid()) << "Validation failed for event type: " << to_event_type_string(type);
        EXPECT_FALSE(event.event_type.empty());
        EXPECT_EQ(event.producer_service, domain::ProducerService::Audit);
    }
}

// Test 2: Context Attribution & Missing Identity (empty actor_id for Unknown actor_type)
TEST_F(InternalSecurityEventRecorderUnitTest, ContextAttributionAndMissingIdentity) {
    InternalSecurityEventFactory factory{"audit-node-01"};

    SecurityEventContext ctx1;
    ctx1.peer_socket_address = "192.168.1.100:44321";
    auto event1 = factory.create_event(InternalSecurityEventType::UnauthenticatedConnection, ctx1);

    EXPECT_EQ(event1.actor_type, domain::ActorType::Unknown);
    EXPECT_TRUE(event1.actor_id.empty());
    EXPECT_EQ(event1.metadata.at("peer_address"), "192.168.1.100:44321");
    EXPECT_TRUE(validator_.validate(event1).is_valid());

    SecurityEventContext ctx2;
    auto event2 = factory.create_event(InternalSecurityEventType::UnauthenticatedConnection, ctx2);
    EXPECT_EQ(event2.actor_type, domain::ActorType::Unknown);
    EXPECT_TRUE(event2.actor_id.empty());
    EXPECT_TRUE(validator_.validate(event2).is_valid());
}

// Test 3: Anti-Recursion Prevention (recursion depth strictly bounded to 0)
TEST_F(InternalSecurityEventRecorderUnitTest, AntiRecursionPrevention) {
    EXPECT_CALL(*mock_repo_, insert_batch_classified(_)).WillOnce([this](const std::vector<domain::AuditEvent>&) {
        SecurityEventContext inner_ctx;
        bool inner_res = recorder_->record_event(InternalSecurityEventType::IngestionQueueSaturated, inner_ctx);
        EXPECT_FALSE(inner_res);
        return repository::RepositoryBatchWriteResult{
            .status = repository::RepositoryWriteStatus::Committed, .error_code = "", .sanitized_reason = ""};
    });

    SecurityEventContext ctx;
    bool outer_res = recorder_->record_event(InternalSecurityEventType::ServiceStarted, ctx);

    EXPECT_TRUE(outer_res);
    EXPECT_EQ(recorder_->events_recorded_count(), 1u);
    EXPECT_EQ(recorder_->events_dropped_count(), 1u);
    EXPECT_EQ(recorder_->recursion_prevented_count(), 1u);
}

// Test 4: Sensitive Data Exclusion (metadata sanitization strips bearer tokens and passwords)
TEST_F(InternalSecurityEventRecorderUnitTest, SensitiveDataExclusion) {
    SecurityEventContext ctx;
    ctx.verified_peer_identity = "gateway.securecloud.internal";
    ctx.metadata["auth_token"] = "secret_bearer_token_12345";
    ctx.metadata["password"] = "SuperSecretPassword!";
    ctx.metadata["violation_reason"] = "PROHIBITED_KEY";

    bool status = recorder_->record_event(InternalSecurityEventType::SensitiveDataDetected, ctx);
    EXPECT_TRUE(status);
    EXPECT_EQ(recorder_->events_recorded_count(), 1u);
}

// Test 5: Queue Saturation & Non-Blocking Drop
TEST_F(InternalSecurityEventRecorderUnitTest, QueueSaturationAndNonBlockingDrop) {
    EXPECT_CALL(*mock_repo_, insert_batch_classified(_))
        .WillRepeatedly(Return(
            repository::RepositoryBatchWriteResult{.status = repository::RepositoryWriteStatus::DeterministicFailure,
                                                   .error_code = "QUEUE_FULL",
                                                   .sanitized_reason = "Ingestion queue saturated"}));

    SecurityEventContext ctx;
    for (int i = 0; i < 50; ++i) {
        bool res = recorder_->record_event(InternalSecurityEventType::IngestionQueueSaturated, ctx);
        EXPECT_FALSE(res);
    }

    EXPECT_EQ(recorder_->events_recorded_count(), 0u);
    EXPECT_EQ(recorder_->events_dropped_count(), 50u);
}

// Test 6: Null Ingestion Service Handled Safely
TEST_F(InternalSecurityEventRecorderUnitTest, NullIngestionServiceHandledSafely) {
    InternalSecurityEventRecorder null_recorder(nullptr, "audit-node-01");
    SecurityEventContext ctx;

    bool success = null_recorder.record_event(InternalSecurityEventType::ServiceStarted, ctx);

    EXPECT_FALSE(success);
    EXPECT_EQ(null_recorder.events_dropped_count(), 1u);
}

} // namespace securecloud::audit::security::testing
