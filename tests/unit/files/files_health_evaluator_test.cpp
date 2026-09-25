#include "files/health/files_health_evaluator.hpp"
#include "securecloud/health/health_status_manager.hpp"

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <stdexcept>
#include <thread>

namespace securecloud::files::health {
namespace {

TEST(FilesHealthEvaluatorTest, InitialStateManualStart) {
    common::health::HealthStatusManager health_manager("files");
    FilesHealthEvaluatorConfig config;
    config.auto_start = false;

    FilesHealthEvaluator evaluator(
        health_manager,
        [] { return false; },
        [] { return false; },
        config);

    EXPECT_FALSE(evaluator.is_running());
    EXPECT_FALSE(evaluator.is_db_healthy());
    EXPECT_FALSE(evaluator.is_s3_healthy());
    EXPECT_FALSE(evaluator.is_ready());
    EXPECT_FALSE(health_manager.evaluate_readiness());
}

TEST(FilesHealthEvaluatorTest, DualDependencyTruthTable) {
    common::health::HealthStatusManager health_manager("files");
    health_manager.set_live(true);

    FilesHealthEvaluatorConfig config;
    config.auto_start = false;

    bool db_status = false;
    bool s3_status = false;

    FilesHealthEvaluator evaluator(
        health_manager,
        [&db_status] { return db_status; },
        [&s3_status] { return s3_status; },
        config);

    // Permutation 1: DB = false, S3 = false -> NOT_SERVING
    db_status = false;
    s3_status = false;
    EXPECT_FALSE(evaluator.evaluate_once());
    EXPECT_FALSE(evaluator.is_db_healthy());
    EXPECT_FALSE(evaluator.is_s3_healthy());
    EXPECT_FALSE(evaluator.is_ready());
    EXPECT_FALSE(health_manager.evaluate_readiness());

    // Permutation 2: DB = false, S3 = true -> NOT_SERVING
    db_status = false;
    s3_status = true;
    EXPECT_FALSE(evaluator.evaluate_once());
    EXPECT_FALSE(evaluator.is_db_healthy());
    EXPECT_TRUE(evaluator.is_s3_healthy());
    EXPECT_FALSE(evaluator.is_ready());
    EXPECT_FALSE(health_manager.evaluate_readiness());

    // Permutation 3: DB = true, S3 = false -> NOT_SERVING
    db_status = true;
    s3_status = false;
    EXPECT_FALSE(evaluator.evaluate_once());
    EXPECT_TRUE(evaluator.is_db_healthy());
    EXPECT_FALSE(evaluator.is_s3_healthy());
    EXPECT_FALSE(evaluator.is_ready());
    EXPECT_FALSE(health_manager.evaluate_readiness());

    // Permutation 4: DB = true, S3 = true -> SERVING
    db_status = true;
    s3_status = true;
    EXPECT_TRUE(evaluator.evaluate_once());
    EXPECT_TRUE(evaluator.is_db_healthy());
    EXPECT_TRUE(evaluator.is_s3_healthy());
    EXPECT_TRUE(evaluator.is_ready());
    EXPECT_TRUE(health_manager.evaluate_readiness());
}

TEST(FilesHealthEvaluatorTest, DynamicTransitionsAndRecovery) {
    common::health::HealthStatusManager health_manager("files");
    health_manager.set_live(true);

    FilesHealthEvaluatorConfig config;
    config.auto_start = false;

    bool db_ok = true;
    bool s3_ok = true;

    FilesHealthEvaluator evaluator(
        health_manager,
        [&db_ok] { return db_ok; },
        [&s3_ok] { return s3_ok; },
        config);

    // 1. Initial healthy state
    EXPECT_TRUE(evaluator.evaluate_once());
    EXPECT_TRUE(evaluator.is_ready());

    // 2. PostgreSQL drops (e.g. connection timeout or failover)
    db_ok = false;
    EXPECT_FALSE(evaluator.evaluate_once());
    EXPECT_FALSE(evaluator.is_db_healthy());
    EXPECT_TRUE(evaluator.is_s3_healthy());
    EXPECT_FALSE(evaluator.is_ready());
    EXPECT_FALSE(health_manager.evaluate_readiness());

    // 3. MinIO S3 drops as well
    s3_ok = false;
    EXPECT_FALSE(evaluator.evaluate_once());
    EXPECT_FALSE(evaluator.is_db_healthy());
    EXPECT_FALSE(evaluator.is_s3_healthy());
    EXPECT_FALSE(evaluator.is_ready());

    // 4. MinIO S3 recovers, but DB is still down
    s3_ok = true;
    EXPECT_FALSE(evaluator.evaluate_once());
    EXPECT_FALSE(evaluator.is_db_healthy());
    EXPECT_TRUE(evaluator.is_s3_healthy());
    EXPECT_FALSE(evaluator.is_ready());

    // 5. PostgreSQL recovers -> Both dependencies back online
    db_ok = true;
    EXPECT_TRUE(evaluator.evaluate_once());
    EXPECT_TRUE(evaluator.is_db_healthy());
    EXPECT_TRUE(evaluator.is_s3_healthy());
    EXPECT_TRUE(evaluator.is_ready());
    EXPECT_TRUE(health_manager.evaluate_readiness());
}

TEST(FilesHealthEvaluatorTest, ExceptionSafety) {
    common::health::HealthStatusManager health_manager("files");
    health_manager.set_live(true);

    FilesHealthEvaluatorConfig config;
    config.auto_start = false;

    // Both probes throw exceptions
    FilesHealthEvaluator evaluator(
        health_manager,
        []() -> bool { throw std::runtime_error("Simulated DB connection failure"); },
        []() -> bool { throw std::logic_error("Simulated MinIO S3 auth failure"); },
        config);

    EXPECT_NO_THROW({
        bool result = evaluator.evaluate_once();
        EXPECT_FALSE(result);
    });

    EXPECT_FALSE(evaluator.is_db_healthy());
    EXPECT_FALSE(evaluator.is_s3_healthy());
    EXPECT_FALSE(evaluator.is_ready());
    EXPECT_FALSE(health_manager.evaluate_readiness());
}

TEST(FilesHealthEvaluatorTest, NonStdExceptionSafety) {
    common::health::HealthStatusManager health_manager("files");
    health_manager.set_live(true);

    FilesHealthEvaluatorConfig config;
    config.auto_start = false;

    // Probe throws non-std exception
    FilesHealthEvaluator evaluator(
        health_manager,
        []() -> bool { throw 42; },
        []() -> bool { return true; },
        config);

    EXPECT_NO_THROW({
        bool result = evaluator.evaluate_once();
        EXPECT_FALSE(result);
    });

    EXPECT_FALSE(evaluator.is_db_healthy());
    EXPECT_TRUE(evaluator.is_s3_healthy());
    EXPECT_FALSE(evaluator.is_ready());
}

TEST(FilesHealthEvaluatorTest, NullProbeSafety) {
    common::health::HealthStatusManager health_manager("files");
    health_manager.set_live(true);

    FilesHealthEvaluatorConfig config;
    config.auto_start = false;

    HealthProbeFn null_db_probe;
    HealthProbeFn null_s3_probe;

    FilesHealthEvaluator evaluator(
        health_manager,
        null_db_probe,
        null_s3_probe,
        config);

    EXPECT_NO_THROW({
        bool result = evaluator.evaluate_once();
        EXPECT_FALSE(result);
    });

    EXPECT_FALSE(evaluator.is_db_healthy());
    EXPECT_FALSE(evaluator.is_s3_healthy());
    EXPECT_FALSE(evaluator.is_ready());
}

TEST(FilesHealthEvaluatorTest, GracefulShutdownImmediateReadinessDrop) {
    common::health::HealthStatusManager health_manager("files");
    health_manager.set_live(true);

    FilesHealthEvaluatorConfig config;
    config.auto_start = false;

    FilesHealthEvaluator evaluator(
        health_manager,
        [] { return true; },
        [] { return true; },
        config);

    EXPECT_TRUE(evaluator.evaluate_once());
    EXPECT_TRUE(evaluator.is_ready());
    EXPECT_TRUE(health_manager.evaluate_readiness());

    // Trigger graceful shutdown on health_manager
    health_manager.set_shutting_down(true);

    // Compound readiness must drop immediately to NOT_SERVING even though dependencies are up
    EXPECT_FALSE(health_manager.evaluate_readiness());
    EXPECT_TRUE(health_manager.is_live()); // Liveness invariant: remains live during draining
}

TEST(FilesHealthEvaluatorTest, BackgroundPollingThreadAutoDetect) {
    common::health::HealthStatusManager health_manager("files");
    health_manager.set_live(true);

    std::atomic<bool> db_online{false};
    std::atomic<bool> s3_online{false};

    FilesHealthEvaluatorConfig config;
    config.check_interval = std::chrono::milliseconds(20);
    config.auto_start = true;

    FilesHealthEvaluator evaluator(
        health_manager,
        [&db_online] { return db_online.load(); },
        [&s3_online] { return s3_online.load(); },
        config);

    EXPECT_TRUE(evaluator.is_running());

    // Initially dependencies are offline
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_FALSE(evaluator.is_ready());
    EXPECT_FALSE(health_manager.evaluate_readiness());

    // Bring both dependencies online in background
    db_online.store(true);
    s3_online.store(true);

    // Wait up to 500ms for background thread to detect
    bool ready_detected = false;
    for (int i = 0; i < 25; ++i) {
        if (evaluator.is_ready() && health_manager.evaluate_readiness()) {
            ready_detected = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    EXPECT_TRUE(ready_detected);

    // Drop MinIO S3 in background
    s3_online.store(false);

    bool degraded_detected = false;
    for (int i = 0; i < 25; ++i) {
        if (!evaluator.is_ready() && !health_manager.evaluate_readiness()) {
            degraded_detected = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    EXPECT_TRUE(degraded_detected);

    // Stop background thread and test idempotency
    evaluator.stop();
    EXPECT_FALSE(evaluator.is_running());
    EXPECT_NO_THROW(evaluator.stop());
}

} // namespace
} // namespace securecloud::files::health
