#include "ingestion/insert_worker_pool.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <stdexcept>
#include <thread>

namespace securecloud::audit::ingestion::testing {

class StubAuditEventRepository : public repository::IAuditEventRepository {
public:
    enum class Behavior {
        Success,
        Timeout,
        ConnectionError
    };

    explicit StubAuditEventRepository(Behavior behavior = Behavior::Success)
        : behavior_(behavior) {}

    bool insert_batch(const std::vector<domain::AuditEvent>& events) override {
        inserted_count_.fetch_add(events.size());
        if (behavior_ == Behavior::Timeout) {
            throw repository::ClickHouseTimeoutException("Query timed out");
        }
        if (behavior_ == Behavior::ConnectionError) {
            throw repository::ClickHouseConnectionException("Connection refused");
        }
        return true;
    }

    std::vector<domain::AuditEvent> query_by_time_range(
        std::chrono::system_clock::time_point,
        std::chrono::system_clock::time_point,
        uint32_t) override {
        return {};
    }

    std::vector<domain::AuditEvent> query_by_producer(
        const std::string&,
        std::chrono::system_clock::time_point,
        std::chrono::system_clock::time_point,
        uint32_t) override {
        return {};
    }

    std::vector<domain::AuditEvent> query_by_correlation_id(
        const std::string&,
        uint32_t) override {
        return {};
    }

    std::optional<domain::AuditEvent> find_by_event_id(const domain::EventId&) override {
        return std::nullopt;
    }

    size_t inserted_count() const { return inserted_count_.load(); }

private:
    Behavior behavior_;
    std::atomic<size_t> inserted_count_{0};
};

class InsertWorkerPoolTest : public ::testing::Test {
protected:
    IngestionEnvelope create_sample_envelope(const std::string& event_id) {
        IngestionEnvelope env;
        auto parsed_id = domain::EventId::from_string(event_id);
        if (parsed_id.has_value()) {
            env.event.event_id = parsed_id.value();
        }
        env.event.occurred_at = std::chrono::system_clock::now();
        env.event.received_at = std::chrono::system_clock::now();
        env.event.event_type = "insert.test.event";
        return env;
    }
};

TEST_F(InsertWorkerPoolTest, SuccessfulBatchInsertion) {
    auto batch_q = std::make_shared<BoundedBatchQueue>(10);
    auto repo = std::make_shared<StubAuditEventRepository>(StubAuditEventRepository::Behavior::Success);

    InsertWorkerPool pool(2, batch_q, repo);
    pool.start();

    IngestionBatch batch;
    auto env = create_sample_envelope("018f6e4a-7b3c-7000-8000-000000000001");
    auto promise = std::make_shared<std::promise<service::IngestionResult>>();
    auto future = promise->get_future();
    env.completion_promise = promise;
    batch.push_back(std::move(env));

    EXPECT_TRUE(batch_q->try_push(std::move(batch)));

    auto res = future.get();
    EXPECT_TRUE(res.success);
    EXPECT_EQ(pool.total_inserted_batches(), 1);
    EXPECT_EQ(pool.total_inserted_events(), 1);
    EXPECT_EQ(repo->inserted_count(), 1);

    pool.stop();
}

TEST_F(InsertWorkerPoolTest, ConnectionFailureCompletesWithUnavailable) {
    auto batch_q = std::make_shared<BoundedBatchQueue>(10);
    auto repo = std::make_shared<StubAuditEventRepository>(StubAuditEventRepository::Behavior::ConnectionError);

    InsertWorkerPool pool(2, batch_q, repo);
    pool.start();

    IngestionBatch batch;
    auto env = create_sample_envelope("018f6e4a-7b3c-7000-8000-000000000001");
    auto promise = std::make_shared<std::promise<service::IngestionResult>>();
    auto future = promise->get_future();
    env.completion_promise = promise;
    batch.push_back(std::move(env));

    EXPECT_TRUE(batch_q->try_push(std::move(batch)));

    auto res = future.get();
    EXPECT_FALSE(res.success);
    EXPECT_EQ(res.error_code, "UNAVAILABLE");
    EXPECT_EQ(pool.total_failed_batches(), 1);

    pool.stop();
}

TEST_F(InsertWorkerPoolTest, TimeoutFailureCompletesWithDeadlineExceeded) {
    auto batch_q = std::make_shared<BoundedBatchQueue>(10);
    auto repo = std::make_shared<StubAuditEventRepository>(StubAuditEventRepository::Behavior::Timeout);

    InsertWorkerPool pool(2, batch_q, repo);
    pool.start();

    IngestionBatch batch;
    auto env = create_sample_envelope("018f6e4a-7b3c-7000-8000-000000000001");
    auto promise = std::make_shared<std::promise<service::IngestionResult>>();
    auto future = promise->get_future();
    env.completion_promise = promise;
    batch.push_back(std::move(env));

    EXPECT_TRUE(batch_q->try_push(std::move(batch)));

    auto res = future.get();
    EXPECT_FALSE(res.success);
    EXPECT_EQ(res.error_code, "DEADLINE_EXCEEDED");
    EXPECT_EQ(pool.total_failed_batches(), 1);

    pool.stop();
}

} // namespace securecloud::audit::ingestion::testing