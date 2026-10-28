#include "ingestion/validation_worker_pool.hpp"
#include "ingestion/in_memory_deduplication_manager.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <thread>

namespace securecloud::audit::ingestion::testing {

class ValidationWorkerPoolTest : public ::testing::Test {
protected:
    IngestionEnvelope create_valid_envelope(const std::string& event_id) {
        IngestionEnvelope env;
        auto parsed_id = domain::EventId::from_string(event_id);
        if (parsed_id.has_value()) {
            env.event.event_id = parsed_id.value();
        }
        env.event.occurred_at = std::chrono::system_clock::now();
        env.event.event_type = "system.test.event";
        env.event.severity = domain::Severity::Info;
        env.event.producer_service = domain::ProducerService::Auth;
        env.event.producer_instance = "auth-01";
        env.event.actor_type = domain::ActorType::System;
        env.event.actor_id = "sys_01";
        env.event.target_type = domain::TargetType::Service;
        env.event.target_id = "target_01";
        env.event.correlation_id = "018f6e4a-7b3c-7000-8000-000000000002";
        return env;
    }
};

TEST_F(ValidationWorkerPoolTest, ValidatesAndRoutesEnvelope) {
    auto input_q = std::make_shared<BoundedIngestionQueue>(10);
    auto output_q = std::make_shared<BoundedIngestionQueue>(10);

    ValidationWorkerPool pool(4, input_q, output_q);
    pool.start();

    auto env = create_valid_envelope("018f6e4a-7b3c-7000-8000-000000000001");
    auto promise = std::make_shared<std::promise<service::IngestionResult>>();
    auto future = promise->get_future();
    env.completion_promise = promise;

    EXPECT_TRUE(input_q->try_push(std::move(env)));

    auto out_env_opt = output_q->pop(std::chrono::milliseconds(1000));
    ASSERT_TRUE(out_env_opt.has_value());
    EXPECT_TRUE(out_env_opt->event.received_at.has_value());
    EXPECT_EQ(pool.total_validated(), 1);

    pool.stop();
}

TEST_F(ValidationWorkerPoolTest, RejectsInvalidEnvelope) {
    auto input_q = std::make_shared<BoundedIngestionQueue>(10);
    auto output_q = std::make_shared<BoundedIngestionQueue>(10);

    ValidationWorkerPool pool(4, input_q, output_q);
    pool.start();

    IngestionEnvelope invalid_env; // Empty required fields
    auto promise = std::make_shared<std::promise<service::IngestionResult>>();
    auto future = promise->get_future();
    invalid_env.completion_promise = promise;

    EXPECT_TRUE(input_q->try_push(std::move(invalid_env)));

    auto res = future.get();
    EXPECT_FALSE(res.success);
    EXPECT_EQ(res.error_code, "INVALID_ARGUMENT");
    EXPECT_EQ(pool.total_rejected(), 1);
    EXPECT_EQ(output_q->size(), 0);

    pool.stop();
}

TEST_F(ValidationWorkerPoolTest, DeduplicatesEventWithInMemoryLru) {
    auto input_q = std::make_shared<BoundedIngestionQueue>(10);
    auto output_q = std::make_shared<BoundedIngestionQueue>(10);
    auto dedup_mgr = std::make_shared<InMemoryLruDeduplicationManager>(100);

    ValidationWorkerPool pool(4, input_q, output_q, dedup_mgr);
    pool.start();

    // First push (unique)
    auto env1 = create_valid_envelope("018f6e4a-7b3c-7000-8000-000000000001");
    EXPECT_TRUE(input_q->try_push(std::move(env1)));
    auto out1 = output_q->pop(std::chrono::milliseconds(1000));
    ASSERT_TRUE(out1.has_value());

    // Second push (duplicate event_id)
    auto env2 = create_valid_envelope("018f6e4a-7b3c-7000-8000-000000000001");
    auto promise = std::make_shared<std::promise<service::IngestionResult>>();
    auto future = promise->get_future();
    env2.completion_promise = promise;

    EXPECT_TRUE(input_q->try_push(std::move(env2)));

    auto res = future.get();
    EXPECT_TRUE(res.success);
    EXPECT_EQ(res.error_code, "DUPLICATE_EVENT_IGNORED");
    EXPECT_EQ(pool.total_duplicates(), 1);
    EXPECT_EQ(output_q->size(), 0);

    pool.stop();
}

} // namespace securecloud::audit::ingestion::testing