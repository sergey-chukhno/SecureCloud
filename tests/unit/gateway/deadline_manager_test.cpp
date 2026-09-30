#include "gateway_config.hpp"
#include "http/deadline_manager.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <httplib.h>
#include <thread>

namespace securecloud::gateway::http {
namespace {

TEST(DeadlineManagerTest, DefaultConfigValues) {
    DeadlineManager mgr;
    const auto& cfg = mgr.config();

    EXPECT_EQ(cfg.auth_timeout_ms, 1000u);
    EXPECT_EQ(cfg.messaging_timeout_ms, 2000u);
    EXPECT_EQ(cfg.files_metadata_timeout_ms, 2000u);
    EXPECT_EQ(cfg.audit_timeout_ms, 1000u);
    EXPECT_EQ(cfg.min_request_deadline_ms, 50u);
    EXPECT_EQ(cfg.max_request_deadline_ms, 10000u);
}

TEST(DeadlineManagerTest, ParseDurationStringValid) {
    // Pure integer milliseconds
    auto res1 = DeadlineManager::parse_duration_string("1500");
    ASSERT_TRUE(res1.has_value());
    EXPECT_EQ(res1->count(), 1500);

    // Milliseconds with 'ms' suffix
    auto res2 = DeadlineManager::parse_duration_string("500ms");
    ASSERT_TRUE(res2.has_value());
    EXPECT_EQ(res2->count(), 500);

    // Case insensitive suffix
    auto res3 = DeadlineManager::parse_duration_string("250MS");
    ASSERT_TRUE(res3.has_value());
    EXPECT_EQ(res3->count(), 250);

    // Seconds with 's' suffix
    auto res4 = DeadlineManager::parse_duration_string("2s");
    ASSERT_TRUE(res4.has_value());
    EXPECT_EQ(res4->count(), 2000);

    // Fractional seconds
    auto res5 = DeadlineManager::parse_duration_string("1.5s");
    ASSERT_TRUE(res5.has_value());
    EXPECT_EQ(res5->count(), 1500);

    // Small fractional seconds
    auto res6 = DeadlineManager::parse_duration_string("0.05s");
    ASSERT_TRUE(res6.has_value());
    EXPECT_EQ(res6->count(), 50);

    // With leading and trailing whitespace
    auto res7 = DeadlineManager::parse_duration_string("   300 ms   ");
    ASSERT_TRUE(res7.has_value());
    EXPECT_EQ(res7->count(), 300);
}

TEST(DeadlineManagerTest, ParseDurationStringInvalid) {
    EXPECT_FALSE(DeadlineManager::parse_duration_string("").has_value());
    EXPECT_FALSE(DeadlineManager::parse_duration_string("   ").has_value());
    EXPECT_FALSE(DeadlineManager::parse_duration_string("abc").has_value());
    EXPECT_FALSE(DeadlineManager::parse_duration_string("0").has_value());
    EXPECT_FALSE(DeadlineManager::parse_duration_string("-50").has_value());
    EXPECT_FALSE(DeadlineManager::parse_duration_string("0ms").has_value());
    EXPECT_FALSE(DeadlineManager::parse_duration_string("2m").has_value());
    EXPECT_FALSE(DeadlineManager::parse_duration_string("1h").has_value());
}

TEST(DeadlineManagerTest, ExtractClientTimeoutFromHeaders) {
    // X-Request-Timeout header
    {
        httplib::Request req;
        req.set_header("X-Request-Timeout", "750ms");
        auto val = DeadlineManager::extract_client_timeout(req);
        ASSERT_TRUE(val.has_value());
        EXPECT_EQ(val->count(), 750);
    }

    // Request-Timeout header
    {
        httplib::Request req;
        req.set_header("Request-Timeout", "3s");
        auto val = DeadlineManager::extract_client_timeout(req);
        ASSERT_TRUE(val.has_value());
        EXPECT_EQ(val->count(), 3000);
    }

    // X-Request-Timeout takes precedence over Request-Timeout
    {
        httplib::Request req;
        req.set_header("X-Request-Timeout", "400ms");
        req.set_header("Request-Timeout", "2s");
        auto val = DeadlineManager::extract_client_timeout(req);
        ASSERT_TRUE(val.has_value());
        EXPECT_EQ(val->count(), 400);
    }

    // Fallback if X-Request-Timeout is invalid
    {
        httplib::Request req;
        req.set_header("X-Request-Timeout", "invalid");
        req.set_header("Request-Timeout", "1200ms");
        auto val = DeadlineManager::extract_client_timeout(req);
        ASSERT_TRUE(val.has_value());
        EXPECT_EQ(val->count(), 1200);
    }

    // Absent headers
    {
        httplib::Request req;
        auto val = DeadlineManager::extract_client_timeout(req);
        EXPECT_FALSE(val.has_value());
    }
}

TEST(DeadlineManagerTest, ComputeEffectiveDeadlineClamping) {
    DeadlineManager mgr;
    const auto default_timeout = std::chrono::milliseconds(5000);

    // No header -> fallback to default
    {
        httplib::Request req;
        auto deadline = mgr.compute_effective_deadline(req, default_timeout);
        EXPECT_EQ(deadline.count(), 5000);
    }

    // Header within bounds [50ms, 10000ms]
    {
        httplib::Request req;
        req.set_header("X-Request-Timeout", "800ms");
        auto deadline = mgr.compute_effective_deadline(req, default_timeout);
        EXPECT_EQ(deadline.count(), 800);
    }

    // Header below minimum floor (10ms < 50ms) -> clamped to 50ms
    {
        httplib::Request req;
        req.set_header("X-Request-Timeout", "10ms");
        auto deadline = mgr.compute_effective_deadline(req, default_timeout);
        EXPECT_EQ(deadline.count(), 50);
    }

    // Header above maximum ceiling (30000ms > 10000ms) -> clamped to 10000ms
    {
        httplib::Request req;
        req.set_header("X-Request-Timeout", "30000ms");
        auto deadline = mgr.compute_effective_deadline(req, default_timeout);
        EXPECT_EQ(deadline.count(), 10000);
    }
}

TEST(DeadlineManagerTest, ComputeDownstreamBudget) {
    DeadlineManager mgr;
    const auto start_tp = std::chrono::steady_clock::now();
    const auto effective_deadline = std::chrono::milliseconds(1000);
    const auto service_timeout = std::chrono::milliseconds(2000);

    // Immediately after start: budget bounded by effective_deadline (1000ms < 2000ms)
    auto budget1 = mgr.compute_downstream_budget(start_tp, effective_deadline, service_timeout);
    EXPECT_LE(budget1.count(), 1000);
    EXPECT_GE(budget1.count(), 950);

    // If service timeout is smaller than remaining deadline:
    const auto tight_service = std::chrono::milliseconds(200);
    auto budget2 = mgr.compute_downstream_budget(start_tp, effective_deadline, tight_service);
    EXPECT_LE(budget2.count(), 200);
    EXPECT_GE(budget2.count(), 180);

    // If start_tp was in the past beyond deadline: budget is 0
    const auto past_tp = start_tp - std::chrono::milliseconds(1500);
    auto budget3 = mgr.compute_downstream_budget(past_tp, effective_deadline, service_timeout);
    EXPECT_EQ(budget3.count(), 0);
}

TEST(DeadlineManagerTest, HasSufficientBudget) {
    DeadlineManager mgr;
    const auto now = std::chrono::steady_clock::now();

    // Sufficient budget
    EXPECT_TRUE(mgr.has_sufficient_budget(now, std::chrono::milliseconds(500)));

    // Expired budget
    const auto past = now - std::chrono::milliseconds(600);
    EXPECT_FALSE(mgr.has_sufficient_budget(past, std::chrono::milliseconds(500)));

    // Exact or insufficient for custom minimum
    const auto edge = now - std::chrono::milliseconds(490);
    EXPECT_FALSE(mgr.has_sufficient_budget(edge, std::chrono::milliseconds(500), std::chrono::milliseconds(20)));
}

} // namespace
} // namespace securecloud::gateway::http
