#include "audit_config.hpp"
#include "query/audit_query_application_service.hpp"
#include "repository/clickhouse_audit_event_repository.hpp"
#include "repository/clickhouse_client.hpp"

#include <chrono>
#include <gtest/gtest.h>

namespace securecloud::audit::integration {

class AuditQueryIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        ClickHouseConfig ch_config;
        ch_config.host = "127.0.0.1";
        ch_config.port = 8123;
        ch_config.db_name = "securecloud_audit";

        client_ = std::make_shared<repository::ClickHouseClient>(ch_config);
        if (!client_->ping()) {
            GTEST_SKIP() << "Live ClickHouse server unavailable at 127.0.0.1:8123. Skipping integration test.";
        }

        repo_ = std::make_shared<repository::ClickHouseAuditEventRepository>(client_);
        QueryConfig q_config;
        app_service_ = std::make_shared<query::AuditQueryApplicationService>(repo_, q_config);
    }

    domain::PeerIdentity audit_peer() {
        domain::PeerIdentity p;
        p.is_authenticated = true;
        p.common_name = "audit.securecloud.internal";
        return p;
    }

    std::shared_ptr<repository::ClickHouseClient> client_;
    std::shared_ptr<repository::ClickHouseAuditEventRepository> repo_;
    std::shared_ptr<query::AuditQueryApplicationService> app_service_;
};

TEST_F(AuditQueryIntegrationTest, LiveClickHouseReadonlyQueryExecutionAndGetById) {
    auto now = std::chrono::system_clock::now();

    domain::AuditEvent ev;
    ev.event_id = domain::EventId::generate_v7();
    ev.occurred_at = now;
    ev.received_at = now;
    ev.producer_service = domain::ProducerService::Auth;
    ev.producer_instance = "auth-01";
    ev.event_type = "user.login.integration";
    ev.severity = domain::Severity::Info;
    ev.actor_type = domain::ActorType::User;
    ev.actor_id = "integration-user";

    ASSERT_TRUE(repo_->insert_batch({ev}));

    // 1. Live Filter Query Execution
    query::AuditQueryFilter filter;
    filter.start_occurred_at = now - std::chrono::minutes(5);
    filter.end_occurred_at = now + std::chrono::minutes(5);
    filter.producer_services = {domain::ProducerService::Auth};
    filter.event_types = {"user.login.integration"};

    query::AuditQueryPageResult result;
    auto status = app_service_->execute_query(audit_peer(), filter, result);

    EXPECT_TRUE(status.ok());
    EXPECT_GE(result.events.size(), 1);

    // 2. Live GetAuditEventById Execution with Partition Pruning
    std::optional<domain::AuditEvent> found_ev;
    auto get_status = app_service_->get_event_by_id(audit_peer(), ev.event_id.to_string(), found_ev);

    EXPECT_TRUE(get_status.ok());
    ASSERT_TRUE(found_ev.has_value());
    EXPECT_EQ(found_ev->event_id, ev.event_id);
}

} // namespace securecloud::audit::integration