#include "repository/audit_repository_exceptions.hpp"
#include "service/audit_query_service_impl.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::service::testing {

class MockQueryRepository : public repository::IAuditEventRepository {
  public:
    bool insert_batch(const std::vector<domain::AuditEvent>&) override { return true; }
    std::vector<domain::AuditEvent> query_by_time_range(std::chrono::system_clock::time_point,
                                                        std::chrono::system_clock::time_point, uint32_t) override {
        return {};
    }
    std::vector<domain::AuditEvent> query_by_producer(const std::string&, std::chrono::system_clock::time_point,
                                                      std::chrono::system_clock::time_point, uint32_t) override {
        return {};
    }
    std::vector<domain::AuditEvent> query_by_correlation_id(const std::string&, uint32_t) override { return {}; }

    std::vector<domain::AuditEvent> execute_paged_query(const query::AuditQueryFilter&,
                                                        const std::optional<query::AuditPageCursor>&, uint32_t,
                                                        size_t) override {
        if (should_throw_timeout)
            throw repository::ClickHouseTimeoutException("Timeout");
        if (should_throw_connection)
            throw repository::ClickHouseConnectionException("Refused");

        std::vector<domain::AuditEvent> evs;
        domain::AuditEvent ev;
        ev.event_id = domain::EventId::generate_v7();
        ev.occurred_at = std::chrono::system_clock::now();
        ev.producer_service = domain::ProducerService::Auth;
        ev.event_type = "user.login";
        evs.push_back(ev);
        return evs;
    }

    std::optional<domain::AuditEvent> find_by_event_id(const domain::EventId& id) override {
        if (should_throw_timeout)
            throw repository::ClickHouseTimeoutException("Timeout");
        domain::AuditEvent ev;
        ev.event_id = id;
        ev.occurred_at = std::chrono::system_clock::now();
        return ev;
    }

    bool should_throw_timeout{false};
    bool should_throw_connection{false};
};

class AuditQueryServiceImplTest : public ::testing::Test {
  protected:
    void SetUp() override {
        repo_ = std::make_shared<MockQueryRepository>();
        QueryConfig cfg;
        cfg.workers = 4;
        app_service_ = std::make_shared<query::AuditQueryApplicationService>(repo_, cfg);
        service_impl_ = std::make_unique<AuditQueryServiceImpl>(app_service_);
    }

    std::shared_ptr<MockQueryRepository> repo_;
    std::shared_ptr<query::AuditQueryApplicationService> app_service_;
    std::unique_ptr<AuditQueryServiceImpl> service_impl_;
};

TEST_F(AuditQueryServiceImplTest, MapSanitizedErrorOnStorageTimeout) {
    repo_->should_throw_timeout = true;

    grpc::ServerContext context;
    securecloud::audit::v1::QueryAuditEventsRequest request;
    request.set_start_occurred_at_ms(1710000000000LL);
    request.set_end_occurred_at_ms(1710086400000LL);

    securecloud::audit::v1::QueryAuditEventsResponse response;
    auto status = service_impl_->QueryAuditEvents(&context, &request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::DEADLINE_EXCEEDED);
}

TEST_F(AuditQueryServiceImplTest, MapSanitizedErrorOnStorageUnavailable) {
    repo_->should_throw_connection = true;

    grpc::ServerContext context;
    securecloud::audit::v1::QueryAuditEventsRequest request;
    request.set_start_occurred_at_ms(1710000000000LL);
    request.set_end_occurred_at_ms(1710086400000LL);

    securecloud::audit::v1::QueryAuditEventsResponse response;
    auto status = service_impl_->QueryAuditEvents(&context, &request, &response);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAVAILABLE);
    EXPECT_EQ(status.error_message(), "Audit storage temporarily unavailable");
}

} // namespace securecloud::audit::service::testing