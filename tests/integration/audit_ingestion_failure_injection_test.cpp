#include "ingestion/audit_ingestion_pipeline.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::ingestion::testing {

class FaultyRepository : public repository::IAuditEventRepository {
public:
    enum class FaultType {
        None,
        Unreachable,
        Timeout
    };

    void set_fault(FaultType fault) { fault_ = fault; }

    bool insert_batch(const std::vector<domain::AuditEvent>& events) override {
        if (fault_ == FaultType::Unreachable) {
            throw repository::ClickHouseConnectionException("ClickHouse cluster unreachable");
        }
        if (fault_ == FaultType::Timeout) {
            throw repository::ClickHouseTimeoutException("Insert query timed out");
        }
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
    FaultType fault_{FaultType::None};
    std::atomic<size_t> inserted_count_{0};
};

static IngestionEnvelope create_valid_envelope() {
    IngestionEnvelope env;
    env.event.event_id = domain::EventId::generate_v7();
    env.event.occurred_at = std::chrono::system_clock::now();
    env.event.event_type = "fault.test";
    env.event.severity = domain::Severity::Info;
    env.event.producer_service = domain::ProducerService::Audit;
    env.event.producer_instance = "fault-injector";
    env.event.actor_type = domain::ActorType::User;
    env.event.actor_id = "user-fault";
    env.event.target_type = domain::TargetType::User;
    env.event.target_id = "target-fault";
    env.event.correlation_id = "corr-fault";
    return env;
}

TEST(AuditIngestionFailureInjectionTest, FailureReturnsNegativeAcknowledgement) {
    auto repo = std::make_shared<FaultyRepository>();
    repo->set_fault(FaultyRepository::FaultType::Unreachable);

    IngestionConfig config{
        .workers = 1,
        .max_queued_events = 10,
        .batch_size = 10,
        .batch_flush_interval_ms = 20,
        .max_event_size_bytes = 65536
    };

    AuditIngestionPipeline pipeline(config, repo);
    pipeline.start();

    auto env = create_valid_envelope();
    auto promise = std::make_shared<std::promise<service::IngestionResult>>();
    auto future = promise->get_future();
    env.completion_promise = promise;

    EXPECT_TRUE(pipeline.submit(std::move(env)));

    auto res = future.get();
    EXPECT_FALSE(res.success);
    EXPECT_EQ(res.error_code, "UNAVAILABLE");
    EXPECT_EQ(repo->inserted_count(), 0);

    pipeline.shutdown();
}

} // namespace securecloud::audit::ingestion::testing