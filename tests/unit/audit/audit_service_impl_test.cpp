#include "service/audit_service_impl.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace securecloud::audit::service::testing {

    class MockAuditEventRepository : public repository::IAuditEventRepository {
    public:
        MOCK_METHOD(bool, insert_batch, (const std::vector<domain::AuditEvent>& events), (override));
        MOCK_METHOD(std::vector<domain::AuditEvent>, query_by_time_range,
                    (std::chrono::system_clock::time_point start, std::chrono::system_clock::time_point end, uint32_t limit), (override));
        MOCK_METHOD(std::vector<domain::AuditEvent>, query_by_producer,
                    (const std::string& producer_service, std::chrono::system_clock::time_point start, std::chrono::system_clock::time_point end, uint32_t limit), (override));
        MOCK_METHOD(std::vector<domain::AuditEvent>, query_by_correlation_id,
                    (const std::string& correlation_id, uint32_t limit), (override));
        MOCK_METHOD(std::optional<domain::AuditEvent>, find_by_event_id,
                    (const domain::EventId& event_id), (override));
    };

    TEST(AuditServiceImplTest, RejectsMissingEvent) {
        auto repo = std::make_shared<MockAuditEventRepository>();
        auto ingestion_service = std::make_shared<AuditIngestionService>(repo);
        AuditServiceImpl service(ingestion_service);

        grpc::ServerContext context;
        v1::SubmitAuditEventRequest request;
        v1::SubmitAuditEventResponse response;

        auto status = service.SubmitAuditEvent(&context, &request, &response);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
    }

} // namespace securecloud::audit::service::testing