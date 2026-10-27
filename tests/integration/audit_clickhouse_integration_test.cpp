#include "repository/schema_initializer.hpp"
#include "repository/clickhouse_client.hpp"
#include "repository/clickhouse_audit_event_repository.hpp"
#include "repository/audit_repository_exceptions.hpp"
#include "domain/audit_event.hpp"

#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include <vector>

namespace securecloud::audit::repository::testing {

class ClickHouseIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        config_.host = "127.0.0.1";
        config_.port = 8123;
        config_.db_name = "securecloud_audit";
        config_.user = "default";
        config_.password = common::configuration::SecretString("clickhouse_dev_admin_secret");
        config_.connect_timeout_ms = 2000;
        config_.request_timeout_ms = 2000;

        client_ = std::make_shared<ClickHouseClient>(config_);

        try {
            std::string res;
            (void)client_->execute_query("SELECT 1", &res, std::chrono::milliseconds(2000));
        } catch (const std::exception& e) {
            GTEST_SKIP() << "ClickHouse ping failed: " << e.what();
        }

        repository_ = std::make_unique<ClickHouseAuditEventRepository>(client_);
    }

    ClickHouseConfig config_;
    std::shared_ptr<ClickHouseClient> client_;
    std::unique_ptr<ClickHouseAuditEventRepository> repository_;

    domain::AuditEvent create_sample_event(const std::string& type, const std::string& producer = "Audit") {
        domain::AuditEvent ev{};
        ev.event_id = domain::EventId::generate_v7();
        ev.occurred_at = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
        ev.received_at = ev.occurred_at;
        ev.event_type = type;
        ev.severity = domain::Severity::Info;
        ev.producer_service = domain::producer_from_string(producer).value_or(domain::ProducerService::Audit);
        ev.producer_instance = "integration-node-01";
        ev.actor_type = domain::ActorType::User;
        ev.actor_id = "actor-integration";
        ev.target_type = domain::TargetType::Unknown;
        ev.target_id = "res-999";
        ev.correlation_id = domain::EventId::generate_v7().to_string();
        ev.metadata = {{"env", "integration_test"}};
        return ev;
    }
};

TEST_F(ClickHouseIntegrationTest, Test1_SchemaCreationAndVerification) {
    SchemaInitializer initializer(config_);
    EXPECT_EQ(initializer.initialize_schema(), SchemaInitResult::Success);
    EXPECT_TRUE(initializer.verify_schema_integrity());
}

TEST_F(ClickHouseIntegrationTest, Test2_SingleEventInsertAndReadBack) {
    auto event = create_sample_event("auth.login_success");
    ASSERT_TRUE(repository_->insert_batch({event}));

    auto fetched = repository_->find_by_event_id(event.event_id);
    ASSERT_TRUE(fetched.has_value());
    EXPECT_EQ(fetched->event_id, event.event_id);
    EXPECT_EQ(fetched->event_type, "auth.login_success");
}

TEST_F(ClickHouseIntegrationTest, Test3_LargeBatchInsert500Events) {
    std::vector<domain::AuditEvent> batch;
    batch.reserve(500);

    for (int i = 0; i < 500; ++i) {
        batch.push_back(create_sample_event("bulk.ingest_event"));
    }

    EXPECT_TRUE(repository_->insert_batch(batch));
}

TEST_F(ClickHouseIntegrationTest, Test4_TimeRangeChronologicalOrder) {
    auto start_time = std::chrono::system_clock::now() - std::chrono::seconds(10);

    auto ev1 = create_sample_event("order.first");
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto ev2 = create_sample_event("order.second");

    ASSERT_TRUE(repository_->insert_batch({ev1, ev2}));

    auto end_time = std::chrono::system_clock::now() + std::chrono::seconds(10);
    auto results = repository_->query_by_time_range(start_time, end_time, 100);

    ASSERT_GE(results.size(), std::size_t{2});
    EXPECT_GE(results[0].occurred_at, results[1].occurred_at);
}

TEST_F(ClickHouseIntegrationTest, Test5_ProducerFilteredQuery) {
    auto start_time = std::chrono::system_clock::now() - std::chrono::seconds(10);
    auto ev = create_sample_event("custom.producer_event", "Audit");

    ASSERT_TRUE(repository_->insert_batch({ev}));

    auto end_time = std::chrono::system_clock::now() + std::chrono::seconds(10);
    auto results = repository_->query_by_producer("Audit", start_time, end_time, 50);

    EXPECT_FALSE(results.empty());
    for (const auto& item : results) {
        EXPECT_EQ(domain::to_string(item.producer_service), domain::to_string(domain::ProducerService::Audit));
    }
}

TEST_F(ClickHouseIntegrationTest, Test6_CorrelationIdTraceReconstruction) {
    std::string trace_id = domain::EventId::generate_v7().to_string();
    auto ev = create_sample_event("trace.span_event");
    ev.correlation_id = trace_id;

    ASSERT_TRUE(repository_->insert_batch({ev}));

    auto trace_results = repository_->query_by_correlation_id(trace_id, 10);
    ASSERT_FALSE(trace_results.empty());
    EXPECT_EQ(trace_results.front().correlation_id, trace_id);
}

TEST_F(ClickHouseIntegrationTest, Test7_DatabaseOutageAndTimeoutHandling) {
    ClickHouseConfig bad_config = config_;
    bad_config.port = 59999;
    bad_config.connect_timeout_ms = 100;

    auto bad_client = std::make_shared<ClickHouseClient>(bad_config);
    ClickHouseAuditEventRepository bad_repo(bad_client);

    auto ev = create_sample_event("fail.event");
    EXPECT_THROW({
        (void)bad_repo.insert_batch({ev});
    }, ClickHouseException);
}

} // namespace securecloud::audit::repository::testing