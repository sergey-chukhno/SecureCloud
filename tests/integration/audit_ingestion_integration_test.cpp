#include "repository/clickhouse_audit_event_repository.hpp"
#include "repository/clickhouse_client.hpp"
#include "security/grpc_producer_identity_validator.hpp"
#include "service/audit_service_impl.hpp"

#include <chrono>
#include <future>
#include <gmock/gmock.h>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <memory>
#include <thread>
#include <vector>

namespace grpc::testing {

class ServerContextTestSpouse {
  public:
    explicit ServerContextTestSpouse(::grpc::ServerContext* ctx) : ctx_(ctx) {}

    void set_auth_context(std::shared_ptr<const ::grpc::AuthContext> auth_context) {
        ctx_->auth_context_ = std::move(auth_context);
    }

  private:
    ::grpc::ServerContext* ctx_;
};

} // namespace grpc::testing

namespace securecloud::audit::integration::testing {

using ::testing::_;
using ::testing::Return;

class TestAuthPropertyIterator : public ::grpc::AuthPropertyIterator {
  public:
    TestAuthPropertyIterator() = default;
};

class TestAuthContext : public ::grpc::AuthContext {
  public:
    explicit TestAuthContext(bool is_authenticated, std::vector<std::pair<std::string, std::string>> properties = {})
        : is_authenticated_(is_authenticated), properties_(std::move(properties)) {}

    [[nodiscard]] bool IsPeerAuthenticated() const override { return is_authenticated_; }

    [[nodiscard]] std::string GetPeerIdentityPropertyName() const override { return "x509_subject_alternative_name"; }

    [[nodiscard]] std::vector<::grpc::string_ref> GetPeerIdentity() const override {
        std::vector<::grpc::string_ref> result;
        for (const auto& [key, value] : properties_) {
            if (key == "x509_subject_alternative_name") {
                result.emplace_back(value.data(), value.size());
            }
        }
        return result;
    }

    [[nodiscard]] std::vector<::grpc::string_ref> FindPropertyValues(const std::string& name) const override {
        std::vector<::grpc::string_ref> result;
        for (const auto& [key, value] : properties_) {
            if (key == name) {
                result.emplace_back(value.data(), value.size());
            }
        }
        return result;
    }

    [[nodiscard]] ::grpc::AuthPropertyIterator begin() const override { return TestAuthPropertyIterator{}; }
    [[nodiscard]] ::grpc::AuthPropertyIterator end() const override { return TestAuthPropertyIterator{}; }

    void AddProperty(const std::string& key, const ::grpc::string_ref& value) override {
        properties_.emplace_back(key, std::string(value.data(), value.size()));
    }

    bool SetPeerIdentityPropertyName(const std::string& /*name*/) override { return true; }

  private:
    bool is_authenticated_{false};
    std::vector<std::pair<std::string, std::string>> properties_;
};

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
        security::GrpcProducerIdentityValidator::set_bypass_peer_verification_for_testing(true);
        mock_client_ = std::make_shared<MockClickHouseClient>();
        repo_ = std::make_shared<repository::ClickHouseAuditEventRepository>(mock_client_);
        ingestion_service_ = std::make_shared<service::AuditIngestionService>(repo_);
        service_impl_ = std::make_unique<service::AuditServiceImpl>(ingestion_service_);
    }

    void TearDown() override {
        security::GrpcProducerIdentityValidator::set_bypass_peer_verification_for_testing(false);
    }

    v1::AuditEventProto build_event(v1::ProducerServiceProto producer, const std::string& instance) {
        v1::AuditEventProto event;
        event.set_event_id("018f6e4a-7b3c-7000-8000-000000000001");
        auto now_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
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

    const size_t num_threads = 4;
    const int events_per_thread = 25;
    std::vector<std::future<void>> futures;

    std::vector<v1::ProducerServiceProto> producers = {v1::PRODUCER_SERVICE_GATEWAY, v1::PRODUCER_SERVICE_AUTH,
                                                       v1::PRODUCER_SERVICE_MESSAGING, v1::PRODUCER_SERVICE_FILES};

    for (size_t i = 0; i < num_threads; ++i) {
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

TEST_F(AuditIngestionIntegrationTest, AuthenticatedMtlsPeerAllowed) {
    security::GrpcProducerIdentityValidator::set_bypass_peer_verification_for_testing(false);
    EXPECT_CALL(*mock_client_, execute_insert(_, _, _)).WillOnce(Return(true));

    grpc::ServerContext context;
    grpc::testing::ServerContextTestSpouse spouse(&context);
    auto auth_ctx = std::make_shared<TestAuthContext>(
        true, std::vector<std::pair<std::string, std::string>>{
                  {"x509_subject_alternative_name", "DNS:auth.securecloud.internal"}});
    spouse.set_auth_context(auth_ctx);

    v1::SubmitAuditEventRequest request;
    *request.mutable_event() = build_event(v1::PRODUCER_SERVICE_AUTH, "auth-01");
    v1::SubmitAuditEventResponse response;

    auto status = service_impl_->SubmitAuditEvent(&context, &request, &response);
    EXPECT_TRUE(status.ok());
    EXPECT_TRUE(response.success());
}

TEST_F(AuditIngestionIntegrationTest, MismatchedProducerIdentityRejectedWithPermissionDenied) {
    security::GrpcProducerIdentityValidator::set_bypass_peer_verification_for_testing(false);

    grpc::ServerContext context;
    grpc::testing::ServerContextTestSpouse spouse(&context);
    // Cert says gateway, but request payload says auth
    auto auth_ctx = std::make_shared<TestAuthContext>(
        true, std::vector<std::pair<std::string, std::string>>{
                  {"x509_subject_alternative_name", "DNS:gateway.securecloud.internal"}});
    spouse.set_auth_context(auth_ctx);

    v1::SubmitAuditEventRequest request;
    *request.mutable_event() = build_event(v1::PRODUCER_SERVICE_AUTH, "auth-01");
    v1::SubmitAuditEventResponse response;

    auto status = service_impl_->SubmitAuditEvent(&context, &request, &response);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

TEST_F(AuditIngestionIntegrationTest, UnauthenticatedContextRejectedWithUnauthenticated) {
    security::GrpcProducerIdentityValidator::set_bypass_peer_verification_for_testing(false);

    grpc::ServerContext unauthenticated_ctx;
    v1::SubmitAuditEventRequest request;
    *request.mutable_event() = build_event(v1::PRODUCER_SERVICE_AUTH, "auth-01");
    v1::SubmitAuditEventResponse response;

    auto status = service_impl_->SubmitAuditEvent(&unauthenticated_ctx, &request, &response);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
}

} // namespace securecloud::audit::integration::testing
