#include "query/audit_query_application_service.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::query::testing {

class MockAuditEventRepository : public repository::IAuditEventRepository {
  public:
    bool insert_batch(const std::vector<domain::AuditEvent>&) override { return true; }
    std::vector<domain::AuditEvent> query_by_time_range(std::chrono::system_clock::time_point,
                                                        std::chrono::system_clock::time_point, uint32_t) override { return {}; }
    std::vector<domain::AuditEvent> query_by_producer(const std::string&, std::chrono::system_clock::time_point,
                                                      std::chrono::system_clock::time_point, uint32_t) override { return {}; }
    std::vector<domain::AuditEvent> query_by_correlation_id(const std::string&, uint32_t) override { return {}; }

    std::vector<domain::AuditEvent> execute_paged_query(
        const AuditQueryFilter& filter,
        const std::optional<AuditPageCursor>&,
        uint32_t, size_t) override {

        query_count++;

        std::vector<domain::AuditEvent> results;
        size_t return_count = return_lookahead ? (filter.page_size + 1) : filter.page_size;

        for (size_t i = 0; i < return_count; ++i) {
            domain::AuditEvent ev;
            ev.event_id = domain::EventId::generate_v7();
            ev.occurred_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(1710000000000LL + i * 1000));
            ev.producer_service = domain::ProducerService::Auth;
            ev.event_type = "user.login";
            results.push_back(ev);
        }
        return results;
    }

    std::optional<domain::AuditEvent> find_by_event_id(const domain::EventId& id) override {
        if (find_should_succeed) {
            domain::AuditEvent ev;
            ev.event_id = id;
            ev.occurred_at = std::chrono::system_clock::now();
            return ev;
        }
        return std::nullopt;
    }

    size_t query_count{0};
    bool return_lookahead{false};
    bool find_should_succeed{true};
};

class AuditQueryApplicationServiceTest : public ::testing::Test {
  protected:
    void SetUp() override {
        mock_repo_ = std::make_shared<MockAuditEventRepository>();
        config_.workers = 2; // Low worker bulkhead for saturation tests
        config_.default_page_limit = 10;
        config_.max_page_limit = 100;
        service_ = std::make_unique<AuditQueryApplicationService>(mock_repo_, config_);
    }

    domain::PeerIdentity build_audit_peer() {
        domain::PeerIdentity p;
        p.is_authenticated = true;
        p.common_name = "audit.securecloud.internal";
        return p;
    }

    domain::PeerIdentity build_auth_peer() {
        domain::PeerIdentity p;
        p.is_authenticated = true;
        p.common_name = "auth.securecloud.internal";
        return p;
    }

    std::shared_ptr<MockAuditEventRepository> mock_repo_;
    QueryConfig config_;
    std::unique_ptr<AuditQueryApplicationService> service_;
};

TEST_F(AuditQueryApplicationServiceTest, ExecuteQuerySuccessAndPaginationLookahead) {
    auto peer = build_audit_peer();
    AuditQueryFilter filter;
    filter.start_occurred_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(1710000000000LL));
    filter.end_occurred_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(1710086400000LL));
    filter.page_size = 5;

    mock_repo_->return_lookahead = true;

    AuditQueryPageResult result;
    auto status = service_->execute_query(peer, filter, result);

    EXPECT_TRUE(status.ok());
    EXPECT_TRUE(result.has_more);
    EXPECT_EQ(result.events.size(), 5);
    EXPECT_FALSE(result.next_page_token.empty());
    EXPECT_EQ(service_->metrics().queries_executed_total.load(), 1);
}

TEST_F(AuditQueryApplicationServiceTest, RejectsUnauthorizedProducerScope) {
    auto peer = build_auth_peer(); // auth service
    AuditQueryFilter filter;
    filter.start_occurred_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(1710000000000LL));
    filter.end_occurred_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(1710086400000LL));
    filter.producer_services = {domain::ProducerService::Files}; // Trying to read Files logs

    AuditQueryPageResult result;
    auto status = service_->execute_query(peer, filter, result);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    EXPECT_EQ(service_->metrics().queries_denied_total.load(), 1);
}

TEST_F(AuditQueryApplicationServiceTest, BulkheadSaturationRejectsRequests) {
    auto peer = build_audit_peer();
    AuditQueryFilter filter;
    filter.start_occurred_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(1710000000000LL));
    filter.end_occurred_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(1710086400000LL));

    // Manually acquire all 2 bulkhead slots
    auto lease1 = service_->bulkhead().try_acquire();
    auto lease2 = service_->bulkhead().try_acquire();

    EXPECT_TRUE(lease1.is_acquired());
    EXPECT_TRUE(lease2.is_acquired());

    // Next request should fail with RESOURCE_EXHAUSTED
    AuditQueryPageResult result;
    auto status = service_->execute_query(peer, filter, result);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::RESOURCE_EXHAUSTED);
    EXPECT_EQ(service_->bulkhead().rejections_total(), 1);
}

} // namespace securecloud::audit::query::testing