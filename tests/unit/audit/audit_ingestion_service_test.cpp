#include "service/audit_ingestion_service.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace securecloud::audit::service::testing {

class MockAuditEventRepository : public repository::IAuditEventRepository {
  public:
    MOCK_METHOD(bool, insert_batch, (const std::vector<domain::AuditEvent>& events), (override));

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

TEST(AuditIngestionServiceTest, RejectsBatchExceedingMaxLimit) {
    auto repo = std::make_shared<MockAuditEventRepository>();
    AuditIngestionService service(repo);

    std::vector<domain::AuditEvent> oversized_batch(101);
    EXPECT_CALL(*repo, insert_batch).Times(0);

    auto result = service.ingest_batch(oversized_batch);
    EXPECT_EQ(result.accepted_count, 0);
    EXPECT_EQ(result.rejected_count, 101);
    EXPECT_FALSE(result.item_results.empty());
    EXPECT_EQ(result.item_results.front().second.error_code, "BATCH_SIZE_EXCEEDED");
}

} // namespace securecloud::audit::service::testing