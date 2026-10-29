#include "service/audit_ingestion_service.hpp"
#include "ingestion/deduplication_cache.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace securecloud::audit::service::testing {

using ::testing::_;
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

class AuditIngestionServiceTest : public ::testing::Test {
  protected:
    domain::AuditEvent build_sample_event(const std::string& uuid_str, const std::string& actor = "user_1") {
        domain::AuditEvent event;
        event.event_id = domain::EventId::from_string(uuid_str).value();
        event.occurred_at = std::chrono::system_clock::now();
        event.event_type = "user.login";
        event.severity = domain::Severity::Info;
        event.producer_service = domain::ProducerService::Auth;
        event.producer_instance = "auth-01";
        event.actor_type = domain::ActorType::User;
        event.actor_id = actor;
        event.target_type = domain::TargetType::Service;
        event.target_id = "sys-01";
        event.correlation_id = "corr-123";
        return event;
    }
};

TEST_F(AuditIngestionServiceTest, RejectsBatchExceedingMaxLimit) {
    auto repo = std::make_shared<MockAuditEventRepository>();
    AuditIngestionService service(repo);

    std::vector<domain::AuditEvent> oversized_batch(101);
    EXPECT_CALL(*repo, insert_batch).Times(0);
    EXPECT_CALL(*repo, insert_batch_classified).Times(0);

    auto result = service.ingest_batch(oversized_batch);
    EXPECT_EQ(result.accepted_count, 0u);
    EXPECT_EQ(result.rejected_count, 101u);
    EXPECT_FALSE(result.item_results.empty());
    EXPECT_EQ(result.item_results.front().second.error_code, "INVALID_ARGUMENT");
}

TEST_F(AuditIngestionServiceTest, IngestSingleNewAndDuplicate) {
    auto repo = std::make_shared<MockAuditEventRepository>();
    auto cache = std::make_shared<ingestion::BoundedDeduplicationCache>(100, std::chrono::minutes(10), 4);
    AuditIngestionService service(repo, cache);

    auto event = build_sample_event("018f6e4a-7b3c-7000-8000-000000000100");

    repository::RepositoryBatchWriteResult success_write{
        .status = repository::RepositoryWriteStatus::Committed,
        .error_code = "",
        .sanitized_reason = ""
    };

    EXPECT_CALL(*repo, insert_batch_classified(_)).Times(1).WillOnce(Return(success_write));

    // 1. Premier passage: PersistedNew
    auto res1 = service.ingest_single(event);
    EXPECT_TRUE(res1.success);
    EXPECT_EQ(res1.outcome_status, ingestion::IngestionOutcomeStatus::PersistedNew);

    // 2. Soumission en doublon: DuplicateCommitted (Le dépôt n'est plus sollicité)
    auto res2 = service.ingest_single(event);
    EXPECT_TRUE(res2.success);
    EXPECT_EQ(res2.outcome_status, ingestion::IngestionOutcomeStatus::DuplicateCommitted);
}

TEST_F(AuditIngestionServiceTest, IngestSinglePayloadConflict) {
    auto repo = std::make_shared<MockAuditEventRepository>();
    auto cache = std::make_shared<ingestion::BoundedDeduplicationCache>(100, std::chrono::minutes(10), 4);
    AuditIngestionService service(repo, cache);

    repository::RepositoryBatchWriteResult success_write{
        .status = repository::RepositoryWriteStatus::Committed,
        .error_code = "",
        .sanitized_reason = ""
    };

    EXPECT_CALL(*repo, insert_batch_classified(_)).Times(1).WillOnce(Return(success_write));

    auto event1 = build_sample_event("018f6e4a-7b3c-7000-8000-000000000101", "user_1");
    auto res1 = service.ingest_single(event1);
    EXPECT_TRUE(res1.success);

    // Même event_id avec une charge utile différente
    auto event2 = build_sample_event("018f6e4a-7b3c-7000-8000-000000000101", "user_2");
    auto res2 = service.ingest_single(event2);
    EXPECT_FALSE(res2.success);
    EXPECT_EQ(res2.outcome_status, ingestion::IngestionOutcomeStatus::IdempotencyConflict);
    EXPECT_EQ(res2.error_code, "ALREADY_EXISTS");
}

TEST_F(AuditIngestionServiceTest, IngestBatchWithIntraBatchDeduplication) {
    auto repo = std::make_shared<MockAuditEventRepository>();
    auto cache = std::make_shared<ingestion::BoundedDeduplicationCache>(100, std::chrono::minutes(10), 4);
    AuditIngestionService service(repo, cache);

    repository::RepositoryBatchWriteResult success_write{
        .status = repository::RepositoryWriteStatus::Committed,
        .error_code = "",
        .sanitized_reason = ""
    };

    EXPECT_CALL(*repo, insert_batch_classified(_)).Times(1).WillOnce(Return(success_write));

    auto event1 = build_sample_event("018f6e4a-7b3c-7000-8000-000000000102", "user_1");
    auto event2 = build_sample_event("018f6e4a-7b3c-7000-8000-000000000103", "user_2");

    // Même event_id qu'event1 mais charge utile en conflit
    auto event1_conflict = build_sample_event("018f6e4a-7b3c-7000-8000-000000000102", "user_different");

    std::vector<domain::AuditEvent> batch{event1, event2, event1_conflict};

    auto batch_res = service.ingest_batch(batch);

    EXPECT_EQ(batch_res.accepted_count, 2u);
    EXPECT_EQ(batch_res.rejected_count, 1u);
    EXPECT_EQ(batch_res.rejected_event_ids.size(), 1u);
    EXPECT_EQ(batch_res.rejected_event_ids[0], event1.event_id);
}

} // namespace securecloud::audit::service::testing