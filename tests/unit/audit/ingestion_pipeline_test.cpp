#include "ingestion/audit_ingestion_pipeline.hpp"
#include "domain/audit_event_validator.hpp"
#include "domain/sensitive_data_guard.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::ingestion::testing {

class MockRepository : public repository::IAuditEventRepository {
public:
    bool insert_batch(const std::vector<domain::AuditEvent>& events) override {
        inserted_count_.fetch_add(events.size());
        return true;
    }

    std::vector<domain::AuditEvent> query_by_time_range(
        std::chrono::system_clock::time_point, std::chrono::system_clock::time_point, uint32_t) override { return {}; }
    std::vector<domain::AuditEvent> query_by_producer(
        const std::string&, std::chrono::system_clock::time_point, std::chrono::system_clock::time_point, uint32_t) override { return {}; }
    std::vector<domain::AuditEvent> query_by_correlation_id(const std::string&, uint32_t) override { return {}; }
    std::optional<domain::AuditEvent> find_by_event_id(const domain::EventId&) override { return std::nullopt; }

    [[nodiscard]] size_t inserted_count() const { return inserted_count_.load(); }

private:
    std::atomic<size_t> inserted_count_{0};
};

static IngestionEnvelope create_valid_envelope(const std::string& event_type = "auth.login") {
    IngestionEnvelope env;
    env.event.event_id = domain::EventId::generate_v7();
    env.event.occurred_at = std::chrono::system_clock::now();
    env.event.event_type = event_type;
    env.event.severity = domain::Severity::Info;
    env.event.producer_service = domain::ProducerService::Audit;
    env.event.producer_instance = "instance-01";
    env.event.actor_type = domain::ActorType::User;
    env.event.actor_id = "user-123";
    env.event.target_type = domain::TargetType::User;
    env.event.target_id = "target-456";
    env.event.correlation_id = "corr-789";
    return env;
}

TEST(AuditIngestionPipelineTest, PipelineLifecycleAndDrain) {
    auto repo = std::make_shared<MockRepository>();
    IngestionConfig config{
        .workers = 2,
        .max_queued_events = 100,
        .batch_size = 10,
        .batch_flush_interval_ms = 50,
        .max_event_size_bytes = 65536
    };

    AuditIngestionPipeline pipeline(config, repo);
    pipeline.start();
    EXPECT_TRUE(pipeline.is_running());

    auto env = create_valid_envelope("pipeline.test");

    // Diagnostic validation checks
    auto val_res = domain::AuditEventValidator::validate(env.event);
    EXPECT_TRUE(val_res.is_valid()) << (val_res.errors().empty() ? "Validation failed" : val_res.errors().front().message);

    auto sensitive_check = domain::SensitiveDataGuard::inspect(env.event);
    EXPECT_TRUE(sensitive_check.is_valid()) << (sensitive_check.errors().empty() ? "Sensitive data guard failed" : sensitive_check.errors().front().message);

    EXPECT_TRUE(pipeline.submit(std::move(env)));

    pipeline.shutdown();
    EXPECT_FALSE(pipeline.is_running());

    EXPECT_EQ(pipeline.validation_pool()->total_rejected(), 0);
    EXPECT_EQ(pipeline.validation_pool()->total_validated(), 1);
    EXPECT_EQ(pipeline.batch_aggregator()->total_batches_dispatched(), 1);
    EXPECT_EQ(pipeline.insert_pool()->total_inserted_events(), 1);
    EXPECT_EQ(repo->inserted_count(), 1);
}

} // namespace securecloud::audit::ingestion::testing