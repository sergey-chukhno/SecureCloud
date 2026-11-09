#include "repository/audit_event_repository_interface.hpp"
#include "service/audit_service_impl.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>

namespace securecloud::audit::service::testing {

using ::testing::_;

class MockRepository : public repository::IAuditEventRepository {
  public:
    MOCK_METHOD(bool, insert_batch, (const std::vector<domain::AuditEvent>&), (override));
    MOCK_METHOD(repository::RepositoryBatchWriteResult, insert_batch_classified,
                (const std::vector<domain::AuditEvent>&), (override));
    MOCK_METHOD(std::vector<domain::AuditEvent>, query_by_time_range,
                (std::chrono::system_clock::time_point, std::chrono::system_clock::time_point, uint32_t), (override));
    MOCK_METHOD(std::vector<domain::AuditEvent>, query_by_producer,
                (const std::string&, std::chrono::system_clock::time_point, std::chrono::system_clock::time_point,
                 uint32_t),
                (override));
    MOCK_METHOD(std::vector<domain::AuditEvent>, query_by_correlation_id, (const std::string&, uint32_t), (override));
    MOCK_METHOD(std::optional<domain::AuditEvent>, find_by_event_id, (const domain::EventId&), (override));
};

class AuditServiceDrainTest : public ::testing::Test {
  protected:
    void SetUp() override {
        security::GrpcProducerIdentityValidator::set_bypass_peer_verification_for_testing(true);
        mock_repo_ = std::make_shared<MockRepository>();
        ingestion_service_ = std::make_shared<AuditIngestionService>(mock_repo_);
        service_ = std::make_unique<AuditServiceImpl>(ingestion_service_);
    }

    void TearDown() override {
        security::GrpcProducerIdentityValidator::set_bypass_peer_verification_for_testing(false);
    }

    std::shared_ptr<MockRepository> mock_repo_;
    std::shared_ptr<AuditIngestionService> ingestion_service_;
    std::unique_ptr<AuditServiceImpl> service_;
};

TEST_F(AuditServiceDrainTest, ServiceRejectsIngressWhenDraining) {
    EXPECT_FALSE(service_->is_draining());

    service_->set_draining(true);
    EXPECT_TRUE(service_->is_draining());

    grpc::ServerContext context;
    v1::SubmitAuditEventRequest request;
    v1::SubmitAuditEventResponse response;

    auto status1 = service_->SubmitAuditEvent(&context, &request, &response);
    EXPECT_EQ(status1.error_code(), grpc::StatusCode::UNAVAILABLE);
    EXPECT_EQ(status1.error_message(), "Audit service is draining; retry via outbox buffer");

    v1::BatchSubmitAuditEventsRequest batch_request;
    v1::BatchSubmitAuditEventsResponse batch_response;

    auto status2 = service_->BatchSubmitAuditEvents(&context, &batch_request, &batch_response);
    EXPECT_EQ(status2.error_code(), grpc::StatusCode::UNAVAILABLE);
    EXPECT_EQ(status2.error_message(), "Audit service is draining; retry via outbox buffer");
}

} // namespace securecloud::audit::service::testing
