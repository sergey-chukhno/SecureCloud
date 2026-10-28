#include "service/audit_service_impl.hpp"

#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::audit::service::testing {

using ::testing::_;
using ::testing::Return;

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

class AuditServiceImplTest : public ::testing::Test {
  protected:
    void SetUp() override {
        mock_repo_ = std::make_shared<MockAuditEventRepository>();
        ingestion_service_ = std::make_shared<AuditIngestionService>(mock_repo_);
        service_ = std::make_unique<AuditServiceImpl>(ingestion_service_);
    }

    v1::AuditEventProto create_valid_proto_event() {
        v1::AuditEventProto event;
        event.set_event_id("018f6e4a-7b3c-7000-8000-000000000001");

        auto now_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
        event.set_occurred_at_ms(now_ms);

        event.set_event_type("user.authentication.success");
        event.set_severity(v1::SEVERITY_INFO);
        event.set_producer_service(v1::PRODUCER_SERVICE_AUTH);
        event.set_producer_instance("auth-node-01");
        event.set_actor_type(v1::ACTOR_TYPE_USER);
        event.set_actor_id("usr_123456");
        event.set_target_type(v1::TARGET_TYPE_SERVICE);
        event.set_target_id("srv_auth");
        event.set_correlation_id("018f6e4a-7b3c-7000-8000-000000000002");
        return event;
    }

    std::shared_ptr<MockAuditEventRepository> mock_repo_;
    std::shared_ptr<AuditIngestionService> ingestion_service_;
    std::unique_ptr<AuditServiceImpl> service_;
};

TEST_F(AuditServiceImplTest, RejectsMissingEvent) {
    grpc::ServerContext context;
    v1::SubmitAuditEventRequest request;
    v1::SubmitAuditEventResponse response;

    auto status = service_->SubmitAuditEvent(&context, &request, &response);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST_F(AuditServiceImplTest, SubmitSingleEventHappyPath) {
    EXPECT_CALL(*mock_repo_, insert_batch(_)).WillOnce(Return(true));

    grpc::ServerContext context;
    v1::SubmitAuditEventRequest request;
    *request.mutable_event() = create_valid_proto_event();
    v1::SubmitAuditEventResponse response;

    auto status = service_->SubmitAuditEvent(&context, &request, &response);

    EXPECT_TRUE(status.ok());
    EXPECT_TRUE(response.success());
    EXPECT_FALSE(response.event_id().empty());
    EXPECT_GT(response.received_at_ms(), 0);
}

TEST_F(AuditServiceImplTest, SubmitBoundedBatchSuccess) {
    EXPECT_CALL(*mock_repo_, insert_batch(_)).WillOnce(Return(true));

    grpc::ServerContext context;
    v1::BatchSubmitAuditEventsRequest request;
    for (int i = 0; i < 100; ++i) {
        *request.add_events() = create_valid_proto_event();
    }
    v1::BatchSubmitAuditEventsResponse response;

    auto status = service_->BatchSubmitAuditEvents(&context, &request, &response);

    EXPECT_TRUE(status.ok());
    EXPECT_EQ(response.accepted_count(), 100u);
    EXPECT_EQ(response.rejected_count(), 0u);
    EXPECT_EQ(response.rejected_event_ids_size(), 0);
}

TEST_F(AuditServiceImplTest, SubmitOversizedBatchRejected) {
    grpc::ServerContext context;
    v1::BatchSubmitAuditEventsRequest request;
    for (int i = 0; i < 101; ++i) {
        *request.add_events() = create_valid_proto_event();
    }
    v1::BatchSubmitAuditEventsResponse response;

    auto status = service_->BatchSubmitAuditEvents(&context, &request, &response);

    EXPECT_TRUE(status.ok());
    EXPECT_EQ(response.accepted_count(), 0u);
    EXPECT_EQ(response.rejected_count(), 101u);
}

TEST_F(AuditServiceImplTest, SchemaValidationFailureMapsToInvalidArgument) {
    grpc::ServerContext context;
    v1::SubmitAuditEventRequest request;
    auto invalid_event = create_valid_proto_event();
    invalid_event.clear_event_type();
    *request.mutable_event() = invalid_event;
    v1::SubmitAuditEventResponse response;

    auto status = service_->SubmitAuditEvent(&context, &request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST_F(AuditServiceImplTest, FutureClockSkewRejection) {
    grpc::ServerContext context;
    v1::SubmitAuditEventRequest request;
    auto skew_event = create_valid_proto_event();

    auto future_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                         (std::chrono::system_clock::now() + std::chrono::minutes(10)).time_since_epoch())
                         .count();
    skew_event.set_occurred_at_ms(future_ms);
    *request.mutable_event() = skew_event;

    v1::SubmitAuditEventResponse response;
    auto status = service_->SubmitAuditEvent(&context, &request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST_F(AuditServiceImplTest, SensitiveDataViolationRejection) {
    grpc::ServerContext context;
    v1::SubmitAuditEventRequest request;
    auto sensitive_event = create_valid_proto_event();
    (*sensitive_event.mutable_metadata())["user_password"] = "SuperSecret123!";
    *request.mutable_event() = sensitive_event;

    v1::SubmitAuditEventResponse response;
    auto status = service_->SubmitAuditEvent(&context, &request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

} // namespace securecloud::audit::service::testing