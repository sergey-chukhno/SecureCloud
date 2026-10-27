#include "service/audit_service_impl.hpp"
#include "repository/clickhouse_audit_event_repository.hpp"
#include "repository/clickhouse_client.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <grpcpp/grpcpp.h>

#include <chrono>
#include <future>
#include <memory>
#include <thread>
#include <vector>

namespace securecloud::audit::integration::testing {

using ::testing::_;
using ::testing::Return;

class MockClickHouseClient : public repository::ClickHouseClient {
public:
    MockClickHouseClient() : repository::ClickHouseClient(ClickHouseConfig{}) {}

    MOCK_METHOD(bool, ping, (std::chrono::milliseconds timeout), (override));
    MOCK_METHOD(bool, execute_insert,
                (const std::string& query, const std::string& body_data, std::chrono::milliseconds timeout),
                (override));
};

class AuditIngestionIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        mock_client_ = std::make_shared<MockClickHouseClient>();
        repo_ = std::make_shared<repository::ClickHouseAuditEventRepository>(mock_client_);
        ingestion_service_ = std::make_shared<service::AuditIngestionService>(repo_);
        service_impl_ = std::make_unique<service::AuditServiceImpl>(ingestion_service_);
    }

    v1::AuditEventProto build_event(v1::ProducerServiceProto producer, const std::string& instance) {
        v1::AuditEventProto event;
        event.set_event_id("018f6e4a-7b3c-7000-8000-000000000001");
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        event.set_occurred_at_ms(now_ms);
        event.set_event_type("system.test.event");
        event.set_severity(v1::SEVERITY_INFO);
        event.set_producer_service(producer);
        event.set_producer_instance(instance);
        event.set_actor_type(v1::ACTOR_TYPE_SYSTEM);
        event.set_actor_id("sys_test");
        event.set_target_type(v1::TARGET_TYPE_SERVICE);
        event.set_target_id("srv_target");
        event.set_correlation_id("018f6e4a-7b3c-7000-8000-000000000002");
        return event;
    }

    std::shared_ptr<MockClickHouseClient> mock_client_;
    std::shared_ptr<repository::ClickHouseAuditEventRepository> repo_;
    std::shared_ptr<service::AuditIngestionService> ingestion_service_;
    std::unique_ptr<service::AuditServiceImpl> service_impl_;
};

TEST_F(AuditIngestionIntegrationTest, ClickHouseOutageMappedToUnavailable) {
    EXPECT_CALL(*mock_client_, execute_insert(_, _, _)).WillOnce(Return(false));

    grpc::ServerContext context;
    v1::SubmitAuditEventRequest request;
    *request.mutable_event() = build_event(v1::PRODUCER_SERVICE_GATEWAY, "gateway-01");
    v1::SubmitAuditEventResponse response;

    auto status = service_impl_->SubmitAuditEvent(&context, &request, &response);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAVAILABLE);
}

TEST_F(AuditIngestionIntegrationTest, EndToEndIngestionPersisted) {
    EXPECT_CALL(*mock_client_, execute_insert(_, _, _)).WillOnce(Return(true));

    grpc::ServerContext context;
    v1::SubmitAuditEventRequest request;
    *request.mutable_event() = build_event(v1::PRODUCER_SERVICE_AUTH, "auth-01");
    v1::SubmitAuditEventResponse response;

    auto status = service_impl_->SubmitAuditEvent(&context, &request, &response);
    EXPECT_TRUE(status.ok());
    EXPECT_TRUE(response.success());
}

TEST_F(AuditIngestionIntegrationTest, ConcurrentMultiProducerIngestion) {
    EXPECT_CALL(*mock_client_, execute_insert(_, _, _)).WillRepeatedly(Return(true));

    const int num_threads = 4;
    const int events_per_thread = 25;
    std::vector<std::future<void>> futures;

    std::vector<v1::ProducerServiceProto> producers = {
        v1::PRODUCER_SERVICE_GATEWAY,
        v1::PRODUCER_SERVICE_AUTH,
        v1::PRODUCER_SERVICE_MESSAGING,
        v1::PRODUCER_SERVICE_FILES
    };

    for (int i = 0; i < num_threads; ++i) {
        futures.push_back(std::async(std::launch::async, [this, i, &producers]() {
            for (int j = 0; j < events_per_thread; ++j) {
                grpc::ServerContext context;
                v1::SubmitAuditEventRequest request;
                *request.mutable_event() = build_event(producers[i], "node-" + std::to_string(i));
                v1::SubmitAuditEventResponse response;

                auto status = service_impl_->SubmitAuditEvent(&context, &request, &response);
                EXPECT_TRUE(status.ok());
            }
        }));
    }

    for (auto& f : futures) {
        f.get();
    }
}

} // namespace securecloud::audit::integration::testing