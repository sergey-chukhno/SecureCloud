#include "gateway_config.hpp"
#include "http/auth/request_context.hpp"
#include "http/middleware/rate_limiter_middleware.hpp"
#include "http/routing/router.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <thread>
#include <vector>

namespace securecloud::gateway::http {
namespace {

class RateLimiterMiddlewareTest : public ::testing::Test {
  protected:
    void SetUp() override {
        simulated_time_ = std::chrono::steady_clock::now();
        clock_fn_ = [this] { return simulated_time_; };
    }

    void advance_time(std::chrono::milliseconds ms) { simulated_time_ += ms; }

    std::chrono::steady_clock::time_point simulated_time_;
    RateLimiterMiddleware::ClockFn clock_fn_;
};

TEST_F(RateLimiterMiddlewareTest, BurstCapacityEnforced) {
    GatewayRateLimitingConfig cfg;
    cfg.enabled = true;
    cfg.burst_capacity = 5;
    cfg.refill_rate_per_sec = 1.0; // 1 token per second
    cfg.max_tracked_clients = 100;
    cfg.client_ttl = std::chrono::seconds(60);

    RateLimiterMiddleware limiter(cfg, clock_fn_);

    // 5 requests allowed
    for (uint32_t i = 0; i < 5; ++i) {
        auto res = limiter.acquire("ip:192.168.1.1");
        EXPECT_TRUE(res.allowed);
        EXPECT_EQ(res.limit, 5u);
        EXPECT_EQ(res.remaining, 4u - i);
        EXPECT_EQ(res.retry_after_sec, 0u);
    }

    // 6th request rejected
    auto res_rejected = limiter.acquire("ip:192.168.1.1");
    EXPECT_FALSE(res_rejected.allowed);
    EXPECT_EQ(res_rejected.remaining, 0u);
    EXPECT_EQ(res_rejected.limit, 5u);
    EXPECT_GE(res_rejected.retry_after_sec, 1u);
}

TEST_F(RateLimiterMiddlewareTest, RefillRateRestoresTokens) {
    GatewayRateLimitingConfig cfg;
    cfg.enabled = true;
    cfg.burst_capacity = 10;
    cfg.refill_rate_per_sec = 2.0; // 2 tokens per second
    cfg.max_tracked_clients = 100;
    cfg.client_ttl = std::chrono::seconds(60);

    RateLimiterMiddleware limiter(cfg, clock_fn_);

    // Exhaust all 10 tokens
    for (int i = 0; i < 10; ++i) {
        auto r = limiter.acquire("user:alice");
        EXPECT_TRUE(r.allowed);
    }
    EXPECT_FALSE(limiter.acquire("user:alice").allowed);

    // Advance 1.5 seconds -> 1.5s * 2.0 tokens/s = 3.0 tokens
    advance_time(std::chrono::milliseconds(1500));

    // First request should succeed
    auto r1 = limiter.acquire("user:alice");
    EXPECT_TRUE(r1.allowed);
    EXPECT_EQ(r1.remaining, 2u); // 3 - 1 = 2 remaining

    auto r2 = limiter.acquire("user:alice");
    EXPECT_TRUE(r2.allowed);
    EXPECT_EQ(r2.remaining, 1u);

    auto r3 = limiter.acquire("user:alice");
    EXPECT_TRUE(r3.allowed);
    EXPECT_EQ(r3.remaining, 0u);

    // Now empty again
    EXPECT_FALSE(limiter.acquire("user:alice").allowed);
}

TEST_F(RateLimiterMiddlewareTest, StandardHeadersEmittedOnAllowedAndRejected) {
    GatewayRateLimitingConfig cfg;
    cfg.enabled = true;
    cfg.burst_capacity = 1;
    cfg.refill_rate_per_sec = 1.0;
    cfg.max_tracked_clients = 10;
    cfg.client_ttl = std::chrono::seconds(60);

    RateLimiterMiddleware limiter(cfg, clock_fn_);

    httplib::Request req;
    req.remote_addr = "10.0.0.1";
    req.headers.emplace("X-Request-ID", "req-12345");

    bool next_called = false;
    auto next = [&](const httplib::Request&, httplib::Response& res) {
        next_called = true;
        res.status = 200;
    };

    // First request: Allowed
    {
        httplib::Response res;
        limiter.process(req, res, next);
        EXPECT_TRUE(next_called);
        EXPECT_EQ(res.get_header_value("X-RateLimit-Limit"), "1");
        EXPECT_EQ(res.get_header_value("X-RateLimit-Remaining"), "0");
    }

    // Second request: Rejected with 429
    {
        next_called = false;
        httplib::Response res;
        limiter.process(req, res, next);
        EXPECT_FALSE(next_called);
        EXPECT_EQ(res.status, 429);
        EXPECT_EQ(res.get_header_value("Content-Type"), "application/problem+json");
        EXPECT_FALSE(res.get_header_value("Retry-After").empty());
        EXPECT_EQ(res.get_header_value("X-RateLimit-Limit"), "1");
        EXPECT_EQ(res.get_header_value("X-RateLimit-Remaining"), "0");
        EXPECT_FALSE(res.get_header_value("X-RateLimit-Reset").empty());

        auto body = nlohmann::json::parse(res.body);
        EXPECT_EQ(body["status"], 429);
        EXPECT_EQ(body["type"], "https://securecloud.internal/errors/rate-limit-exceeded");
        EXPECT_EQ(body["title"], "Too Many Requests");
        EXPECT_EQ(body["error"]["code"], "RATE_LIMIT_EXCEEDED");
        EXPECT_EQ(body["request_id"], "req-12345");
    }
}

TEST_F(RateLimiterMiddlewareTest, AuthenticatedUserTakesPrecedenceOverIp) {
    GatewayRateLimitingConfig cfg;
    cfg.enabled = true;
    cfg.burst_capacity = 2;
    cfg.refill_rate_per_sec = 0.5;

    RateLimiterMiddleware limiter(cfg, clock_fn_);

    AuthenticatedContext auth_ctx("usr-alice-42", "dev-1", "sess-1",
                                  securecloud::auth::v1::AUTHENTICATION_LEVEL_MFA_VERIFIED, {"messages:read"},
                                  9999999999LL);

    // Request from IP A with Alice authenticated
    {
        RequestContext req_ctx("req-1", "1.2.3.4", 1000, auth_ctx);
        ScopedRequestContext scoped_ctx(req_ctx);

        httplib::Request req;
        req.remote_addr = "1.2.3.4";
        EXPECT_EQ(RateLimiterMiddleware::resolve_client_key(req), "user:usr-alice-42");

        auto res = limiter.acquire(RateLimiterMiddleware::resolve_client_key(req));
        EXPECT_TRUE(res.allowed);
        EXPECT_EQ(res.remaining, 1u);
    }

    // Request from different IP B with Alice authenticated shares same bucket!
    {
        RequestContext req_ctx("req-2", "99.88.77.66", 1001, auth_ctx);
        ScopedRequestContext scoped_ctx(req_ctx);

        httplib::Request req;
        req.remote_addr = "99.88.77.66";
        EXPECT_EQ(RateLimiterMiddleware::resolve_client_key(req), "user:usr-alice-42");

        auto res = limiter.acquire(RateLimiterMiddleware::resolve_client_key(req));
        EXPECT_TRUE(res.allowed);
        EXPECT_EQ(res.remaining, 0u);
    }

    // Third request from yet another IP C with Alice authenticated is rejected!
    {
        RequestContext req_ctx("req-3", "55.44.33.22", 1002, auth_ctx);
        ScopedRequestContext scoped_ctx(req_ctx);

        httplib::Request req;
        req.remote_addr = "55.44.33.22";
        auto res = limiter.acquire(RateLimiterMiddleware::resolve_client_key(req));
        EXPECT_FALSE(res.allowed);
    }
}

TEST_F(RateLimiterMiddlewareTest, IpFallbackForUnauthenticated) {
    GatewayRateLimitingConfig cfg;
    cfg.enabled = true;
    cfg.burst_capacity = 2;

    RateLimiterMiddleware limiter(cfg, clock_fn_);

    // Without AuthenticatedContext, falls back to IP
    httplib::Request req1;
    req1.remote_addr = "192.168.1.10";
    EXPECT_EQ(RateLimiterMiddleware::resolve_client_key(req1), "ip:192.168.1.10");

    httplib::Request req2;
    req2.remote_addr = "192.168.1.20";
    EXPECT_EQ(RateLimiterMiddleware::resolve_client_key(req2), "ip:192.168.1.20");

    // X-Forwarded-For fallback
    httplib::Request req_xff;
    req_xff.headers.emplace("X-Forwarded-For", "203.0.113.195, 70.41.3.18");
    EXPECT_EQ(RateLimiterMiddleware::resolve_client_key(req_xff), "ip:203.0.113.195");

    // Separate IP buckets
    EXPECT_TRUE(limiter.acquire("ip:192.168.1.10").allowed);
    EXPECT_TRUE(limiter.acquire("ip:192.168.1.10").allowed);
    EXPECT_FALSE(limiter.acquire("ip:192.168.1.10").allowed);

    // Other IP is completely unaffected
    EXPECT_TRUE(limiter.acquire("ip:192.168.1.20").allowed);
    EXPECT_TRUE(limiter.acquire("ip:192.168.1.20").allowed);
    EXPECT_FALSE(limiter.acquire("ip:192.168.1.20").allowed);
}

TEST_F(RateLimiterMiddlewareTest, MemoryBoundednessUnderFlood) {
    GatewayRateLimitingConfig cfg;
    cfg.enabled = true;
    cfg.burst_capacity = 5;
    cfg.refill_rate_per_sec = 10.0;
    cfg.max_tracked_clients = 200; // Small ceiling for testing
    cfg.client_ttl = std::chrono::seconds(300);

    RateLimiterMiddleware limiter(cfg, clock_fn_);

    // Flood with 50,000 distinct IP addresses (attacker simulating IP spoofing)
    for (int i = 0; i < 50000; ++i) {
        std::string spoofed_ip = "ip:10." + std::to_string((i / 65536) % 256) + "." + std::to_string((i / 256) % 256) +
                                 "." + std::to_string(i % 256);
        auto res = limiter.acquire(spoofed_ip);
        EXPECT_TRUE(res.allowed);
    }

    // Assert strictly bounded memory: tracked client count must never exceed max_tracked_clients
    EXPECT_LE(limiter.tracked_client_count(), 200u);
    EXPECT_EQ(limiter.tracked_client_count(), 200u);
}

TEST_F(RateLimiterMiddlewareTest, TtlExpirationPrunesIdleClients) {
    GatewayRateLimitingConfig cfg;
    cfg.enabled = true;
    cfg.burst_capacity = 2;
    cfg.refill_rate_per_sec = 0.1;
    cfg.max_tracked_clients = 100;
    cfg.client_ttl = std::chrono::seconds(10); // 10s TTL

    RateLimiterMiddleware limiter(cfg, clock_fn_);

    // Exhaust client A
    EXPECT_TRUE(limiter.acquire("ip:1.1.1.1").allowed);
    EXPECT_TRUE(limiter.acquire("ip:1.1.1.1").allowed);
    EXPECT_FALSE(limiter.acquire("ip:1.1.1.1").allowed);
    EXPECT_EQ(limiter.tracked_client_count(), 1u);

    // Advance 5 seconds (not yet expired)
    advance_time(std::chrono::seconds(5));
    EXPECT_EQ(limiter.prune_expired(), 0u);
    EXPECT_EQ(limiter.tracked_client_count(), 1u);

    // Advance past TTL (another 6 seconds -> total 11s elapsed)
    advance_time(std::chrono::seconds(6));
    EXPECT_EQ(limiter.prune_expired(), 1u);
    EXPECT_EQ(limiter.tracked_client_count(), 0u);

    // When client returns after TTL, they receive a fresh full bucket!
    auto fresh_res = limiter.acquire("ip:1.1.1.1");
    EXPECT_TRUE(fresh_res.allowed);
    EXPECT_EQ(fresh_res.remaining, 1u);
}

TEST_F(RateLimiterMiddlewareTest, MultiThreadedConcurrencyStressTest) {
    GatewayRateLimitingConfig cfg;
    cfg.enabled = true;
    cfg.burst_capacity = 500;
    cfg.refill_rate_per_sec = 50.0;
    cfg.max_tracked_clients = 1000;
    cfg.client_ttl = std::chrono::seconds(300);

    RateLimiterMiddleware limiter(cfg); // Use real clock for multi-threading

    constexpr int k_threads = 24;
    constexpr int k_ops_per_thread = 200;

    std::vector<std::thread> workers;
    workers.reserve(k_threads);

    for (int t = 0; t < k_threads; ++t) {
        workers.emplace_back([&, t] {
            for (int i = 0; i < k_ops_per_thread; ++i) {
                // Thread accesses both shared keys and partitioned keys
                std::string key = (i % 2 == 0) ? "user:shared_hotspot" : "ip:worker_" + std::to_string(t);
                (void)limiter.acquire(key);
            }
        });
    }

    for (auto& w : workers) {
        w.join();
    }

    EXPECT_LE(limiter.tracked_client_count(), 1000u);
}

} // namespace
} // namespace securecloud::gateway::http
