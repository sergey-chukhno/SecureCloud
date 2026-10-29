#include "service/audit_ingestion_service.hpp"
#include "ingestion/deduplication_cache.hpp"
#include "ingestion/deduplication_metrics.hpp"

#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>

namespace securecloud::audit::testing {

class PipelineMockRepository : public repository::IAuditEventRepository {
  public:
    bool insert_batch(const std::vector<domain::AuditEvent>& events) override {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            if (pause_writes_) {
                cv_pause_.wait(lock, [this] { return !pause_writes_; });
            }
        }

        if (fail_mode_ == FailMode::DeterministicFailure) {
            return false;
        }

        insert_count_.fetch_add(1, std::memory_order_relaxed);
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& evt : events) {
            inserted_events_.push_back(evt);
        }
        return true;
    }

    repository::RepositoryBatchWriteResult
    insert_batch_classified(const std::vector<domain::AuditEvent>& events) override {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            if (pause_writes_) {
                cv_pause_.wait(lock, [this] { return !pause_writes_; });
            }
        }

        if (fail_mode_ == FailMode::DeterministicFailure) {
            return repository::RepositoryBatchWriteResult{
                .status = repository::RepositoryWriteStatus::DeterministicFailure,
                .error_code = "UNAVAILABLE",
                .sanitized_reason = "Connection refused"
            };
        }

        if (fail_mode_ == FailMode::AmbiguousOutcome) {
            return repository::RepositoryBatchWriteResult{
                .status = repository::RepositoryWriteStatus::AmbiguousOutcome,
                .error_code = "DEADLINE_EXCEEDED",
                .sanitized_reason = "HTTP socket timeout"
            };
        }

        insert_count_.fetch_add(1, std::memory_order_relaxed);
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& evt : events) {
            inserted_events_.push_back(evt);
        }
        return repository::RepositoryBatchWriteResult{
            .status = repository::RepositoryWriteStatus::Committed,
            .error_code = "",
            .sanitized_reason = ""
        };
    }

    std::vector<domain::AuditEvent> query_by_time_range(std::chrono::system_clock::time_point,
                                                        std::chrono::system_clock::time_point, uint32_t) override {
        std::lock_guard<std::mutex> lock(mutex_);
        return inserted_events_;
    }

    std::vector<domain::AuditEvent> query_by_producer(const std::string&, std::chrono::system_clock::time_point,
                                                     std::chrono::system_clock::time_point, uint32_t) override {
        std::lock_guard<std::mutex> lock(mutex_);
        return inserted_events_;
    }

    std::vector<domain::AuditEvent> query_by_correlation_id(const std::string&, uint32_t) override {
        std::lock_guard<std::mutex> lock(mutex_);
        return inserted_events_;
    }

    std::optional<domain::AuditEvent> find_by_event_id(const domain::EventId& event_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& evt : inserted_events_) {
            if (evt.event_id == event_id) {
                return evt;
            }
        }
        return std::nullopt;
    }

    std::vector<repository::DuplicateEventCount> find_duplicate_event_counts(uint32_t limit = 100) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::unordered_map<domain::EventId, uint64_t> counts;
        for (const auto& evt : inserted_events_) {
            counts[evt.event_id]++;
        }

        std::vector<repository::DuplicateEventCount> dups;
        for (const auto& [id, count] : counts) {
            if (count > 1) {
                dups.push_back(repository::DuplicateEventCount{.event_id = id, .occurrences = count});
            }
        }
        if (dups.size() > limit) {
            dups.resize(limit);
        }
        return dups;
    }

    enum class FailMode { None, DeterministicFailure, AmbiguousOutcome };

    void set_fail_mode(FailMode mode) { fail_mode_ = mode; }

    void set_pause_writes(bool pause) {
        std::lock_guard<std::mutex> lock(mutex_);
        pause_writes_ = pause;
        if (!pause) {
            cv_pause_.notify_all();
        }
    }

    uint32_t get_insert_count() const noexcept { return insert_count_.load(std::memory_order_relaxed); }
    size_t get_total_inserted_records() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return inserted_events_.size();
    }

  private:
    mutable std::mutex mutex_;
    std::condition_variable cv_pause_;
    bool pause_writes_{false};
    FailMode fail_mode_{FailMode::None};
    std::atomic<uint32_t> insert_count_{0};
    std::vector<domain::AuditEvent> inserted_events_;
};

class AuditDeduplicationPipelineTest : public ::testing::Test {
  protected:
    void SetUp() override {
        ingestion::DeduplicationMetrics::instance().reset();
    }

    domain::AuditEvent build_sample_event(const std::string& uuid_str, const std::string& actor = "user_1") {
        domain::AuditEvent event;
        event.event_id = domain::EventId::from_string(uuid_str).value();
        event.occurred_at = std::chrono::system_clock::now();
        event.event_type = "user.login";
        event.severity = domain::Severity::Info;
        event.producer_service = domain::ProducerService::Auth;
        event.producer_instance = "auth-01";
        event.actor_type = domain::ActorType::User;
        event.actor_id = actor;
        event.target_type = domain::TargetType::Service;
        event.target_id = "sys-01";
        event.correlation_id = "corr-123";
        return event;
    }
};

TEST_F(AuditDeduplicationPipelineTest, IntraBatchDuplicateSamePayloadPersistedOnce) {
    auto repo = std::make_shared<PipelineMockRepository>();
    auto cache = std::make_shared<ingestion::BoundedDeduplicationCache>(100, std::chrono::minutes(10), 4);
    service::AuditIngestionService service(repo, cache);

    auto event = build_sample_event("018f6e4a-7b3c-7000-8000-000000000301");
    std::vector<domain::AuditEvent> batch{event, event, event};

    auto res = service.ingest_batch(batch);

    EXPECT_EQ(res.accepted_count, 3u);
    EXPECT_EQ(res.rejected_count, 0u);
    EXPECT_EQ(repo->get_total_inserted_records(), 1u);
    EXPECT_EQ(repo->get_insert_count(), 1u);
}

TEST_F(AuditDeduplicationPipelineTest, IntraBatchConflictingPayloadRejected) {
    auto repo = std::make_shared<PipelineMockRepository>();
    auto cache = std::make_shared<ingestion::BoundedDeduplicationCache>(100, std::chrono::minutes(10), 4);
    service::AuditIngestionService service(repo, cache);

    auto event_valid = build_sample_event("018f6e4a-7b3c-7000-8000-000000000302", "actor_A");
    auto event_conflict = build_sample_event("018f6e4a-7b3c-7000-8000-000000000302", "actor_B");

    std::vector<domain::AuditEvent> batch{event_valid, event_conflict};

    auto res = service.ingest_batch(batch);

    EXPECT_EQ(res.accepted_count, 1u);
    EXPECT_EQ(res.rejected_count, 1u);
    EXPECT_EQ(res.rejected_event_ids.size(), 1u);
    EXPECT_EQ(res.rejected_event_ids[0], event_valid.event_id);
    EXPECT_EQ(repo->get_total_inserted_records(), 1u);
}

TEST_F(AuditDeduplicationPipelineTest, CrossBatchDuplicateShortCircuitedWithoutDatabaseWrite) {
    auto repo = std::make_shared<PipelineMockRepository>();
    auto cache = std::make_shared<ingestion::BoundedDeduplicationCache>(100, std::chrono::minutes(10), 4);
    service::AuditIngestionService service(repo, cache);

    auto event = build_sample_event("018f6e4a-7b3c-7000-8000-000000000303");

    // First submission
    auto res1 = service.ingest_single(event);
    EXPECT_TRUE(res1.success);
    EXPECT_EQ(res1.outcome_status, ingestion::IngestionOutcomeStatus::PersistedNew);
    EXPECT_EQ(repo->get_insert_count(), 1u);

    // Second submission (Cross-batch retry)
    auto res2 = service.ingest_single(event);
    EXPECT_TRUE(res2.success);
    EXPECT_EQ(res2.outcome_status, ingestion::IngestionOutcomeStatus::DuplicateCommitted);
    EXPECT_EQ(res2.received_at, res1.received_at);

    // Zero additional database inserts
    EXPECT_EQ(repo->get_insert_count(), 1u);
}

TEST_F(AuditDeduplicationPipelineTest, ConcurrentSubmissionsOfSameEventCoalesceWithoutRace) {
    auto repo = std::make_shared<PipelineMockRepository>();
    auto cache = std::make_shared<ingestion::BoundedDeduplicationCache>(100, std::chrono::minutes(10), 4);
    service::AuditIngestionService service(repo, cache);

    auto event = build_sample_event("018f6e4a-7b3c-7000-8000-000000000304");

    const int thread_count = 32;
    std::vector<std::thread> threads;
    std::vector<service::IngestionResult> results(thread_count);

    for (int i = 0; i < thread_count; ++i) {
        threads.emplace_back([&service, event, &results, i] {
            results[i] = service.ingest_single(event);
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    for (int i = 0; i < thread_count; ++i) {
        EXPECT_TRUE(results[i].success);
    }

    EXPECT_EQ(repo->get_total_inserted_records(), 1u);
    EXPECT_EQ(repo->get_insert_count(), 1u);
}

TEST_F(AuditDeduplicationPipelineTest, VolatileQueueAdmissionNeverAcknowledgedBeforeCommit) {
    auto repo = std::make_shared<PipelineMockRepository>();
    auto cache = std::make_shared<ingestion::BoundedDeduplicationCache>(100, std::chrono::minutes(10), 4);
    service::AuditIngestionService service(repo, cache);

    auto event = build_sample_event("018f6e4a-7b3c-7000-8000-000000000305");

    repo->set_pause_writes(true);

    std::atomic<bool> completed{false};
    service::IngestionResult res;

    std::thread t([&] {
        res = service.ingest_single(event);
        completed.store(true);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_FALSE(completed.load());
    EXPECT_EQ(cache->committed_count(), 0u);

    repo->set_pause_writes(false);
    t.join();

    EXPECT_TRUE(completed.load());
    EXPECT_TRUE(res.success);
    EXPECT_EQ(cache->committed_count(), 1u);
}

TEST_F(AuditDeduplicationPipelineTest, DatabaseFailureAndTimeoutRollbackAllowsCleanRetry) {
    auto repo = std::make_shared<PipelineMockRepository>();
    auto cache = std::make_shared<ingestion::BoundedDeduplicationCache>(100, std::chrono::minutes(10), 4);
    service::AuditIngestionService service(repo, cache);

    auto event = build_sample_event("018f6e4a-7b3c-7000-8000-000000000306");

    // Attempt 1: Database failure
    repo->set_fail_mode(PipelineMockRepository::FailMode::AmbiguousOutcome);

    auto res1 = service.ingest_single(event);
    EXPECT_FALSE(res1.success);
    EXPECT_EQ(res1.outcome_status, ingestion::IngestionOutcomeStatus::PersistenceAmbiguous);
    EXPECT_EQ(cache->size(), 0u);

    // Attempt 2: Retry succeeds
    repo->set_fail_mode(PipelineMockRepository::FailMode::None);

    auto res2 = service.ingest_single(event);
    EXPECT_TRUE(res2.success);
    EXPECT_EQ(res2.outcome_status, ingestion::IngestionOutcomeStatus::PersistedNew);
    EXPECT_EQ(cache->committed_count(), 1u);
}

TEST_F(AuditDeduplicationPipelineTest, SimulatedServiceRestartBehavior) {
    auto repo = std::make_shared<PipelineMockRepository>();
    auto cache1 = std::make_shared<ingestion::BoundedDeduplicationCache>(100, std::chrono::minutes(10), 4);
    service::AuditIngestionService service1(repo, cache1);

    auto event = build_sample_event("018f6e4a-7b3c-7000-8000-000000000307");

    auto res1 = service1.ingest_single(event);
    EXPECT_TRUE(res1.success);

    // Service restart: new empty cache, same underlying repository
    auto cache2 = std::make_shared<ingestion::BoundedDeduplicationCache>(100, std::chrono::minutes(10), 4);
    service::AuditIngestionService service2(repo, cache2);

    auto res2 = service2.ingest_single(event);
    EXPECT_TRUE(res2.success);

    // Analytical duplicate detection query identifies the duplicate
    auto dups = repo->find_duplicate_event_counts();
    EXPECT_EQ(dups.size(), 1u);
    EXPECT_EQ(dups[0].event_id, event.event_id);
    EXPECT_EQ(dups[0].occurrences, 2u);
}

} // namespace securecloud::audit::testing