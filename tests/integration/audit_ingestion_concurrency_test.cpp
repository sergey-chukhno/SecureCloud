#include "ingestion/audit_ingestion_pipeline.hpp"

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

namespace securecloud::audit::ingestion::testing {

class ConcurrentMockRepository : public repository::IAuditEventRepository {
  public:
    bool insert_batch(const std::vector<domain::AuditEvent>& events) override {
        inserted_count_.fetch_add(events.size(), std::memory_order_relaxed);
        return true;
    }

    std::vector<domain::AuditEvent> query_by_time_range(std::chrono::system_clock::time_point,
                                                        std::chrono::system_clock::time_point, uint32_t) override {
        return {};
    }
    std::vector<domain::AuditEvent> query_by_producer(const std::string&, std::chrono::system_clock::time_point,
                                                      std::chrono::system_clock::time_point, uint32_t) override {
        return {};
    }
    std::vector<domain::AuditEvent> query_by_correlation_id(const std::string&, uint32_t) override { return {}; }
    std::optional<domain::AuditEvent> find_by_event_id(const domain::EventId&) override { return std::nullopt; }

    [[nodiscard]] size_t inserted_count() const { return inserted_count_.load(std::memory_order_relaxed); }

  private:
    std::atomic<size_t> inserted_count_{0};
};

static IngestionEnvelope create_valid_envelope(size_t thread_id) {
    IngestionEnvelope env;
    env.event.event_id = domain::EventId::generate_v7();
    env.event.occurred_at = std::chrono::system_clock::now();
    env.event.event_type = "concurrency.test";
    env.event.severity = domain::Severity::Info;
    env.event.producer_service = domain::ProducerService::Audit;
    env.event.producer_instance = "worker-instance-" + std::to_string(thread_id);
    env.event.actor_type = domain::ActorType::User;
    env.event.actor_id = "user-stress";
    env.event.target_type = domain::TargetType::User;
    env.event.target_id = "target-stress";
    env.event.correlation_id = "corr-" + std::to_string(thread_id);
    return env;
}

TEST(AuditIngestionConcurrencyTest, HighConcurrencyProducerStress) {
    auto repo = std::make_shared<ConcurrentMockRepository>();
    IngestionConfig config{.workers = 4,
                           .max_queued_events = 10000,
                           .batch_size = 500,
                           .batch_flush_interval_ms = 50,
                           .max_event_size_bytes = 65536};

    AuditIngestionPipeline pipeline(config, repo);
    pipeline.start();

    constexpr size_t num_threads = 20;
    constexpr size_t events_per_thread = 2500; // 50,000 total events
    std::atomic<size_t> submitted_count{0};

    std::vector<std::thread> producers;
    producers.reserve(num_threads);

    for (size_t t = 0; t < num_threads; ++t) {
        producers.emplace_back([&pipeline, &submitted_count, t]() {
            for (size_t i = 0; i < events_per_thread; ++i) {
                auto env = create_valid_envelope(t);
                while (!pipeline.submit(env)) {
                    std::this_thread::yield();
                }
                submitted_count.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    for (auto& t : producers) {
        t.join();
    }

    EXPECT_EQ(submitted_count.load(), num_threads * events_per_thread);

    pipeline.shutdown();
    EXPECT_EQ(repo->inserted_count(), num_threads * events_per_thread);
}

} // namespace securecloud::audit::ingestion::testing