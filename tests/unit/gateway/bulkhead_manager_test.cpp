#include "gateway_config.hpp"
#include "grpc/auth_client_interface.hpp"
#include "http/auth/authenticated_context.hpp"
#include "http/auth/request_context.hpp"
#include "http/proxy/auth_proxy_handler.hpp"
#include "http/resilience/bulkhead_manager.hpp"
#include "http/resilience/deadline_manager.hpp"
#include "http/resilience/retry_policy.hpp"
#include "http/routing/gateway_route_registrar.hpp"
#include "http/routing/router.hpp"
#include "securecloud/health/health_status_manager.hpp"

#include <atomic>
#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::gateway::http {
namespace {

using ::testing::_;
using ::testing::Return;

class MockAuthClient : public securecloud::gateway::grpc::IAuthClient {
  public:
    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::AuthenticateResponse>, authenticate,
                (const securecloud::auth::v1::AuthenticateRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::ValidateSessionResponse>, validate_session,
                (const securecloud::auth::v1::ValidateSessionRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::RefreshSessionResponse>, refresh_session,
                (const securecloud::auth::v1::RefreshSessionRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::RevokeSessionResponse>, revoke_session,
                (const securecloud::auth::v1::RevokeSessionRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::GetUserResponse>, get_user,
                (const securecloud::auth::v1::GetUserRequest& req, securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::RegisterDeviceResponse>, register_device,
                (const securecloud::auth::v1::RegisterDeviceRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::GetCryptoIdentityResponse>,
                get_crypto_identity,
                (const securecloud::auth::v1::GetCryptoIdentityRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));

    MOCK_METHOD(securecloud::gateway::grpc::Result<securecloud::auth::v1::GetDeviceCryptoDirectoryResponse>,
                get_device_crypto_directory,
                (const securecloud::auth::v1::GetDeviceCryptoDirectoryRequest& req,
                 securecloud::gateway::grpc::ClientCallContext& ctx),
                (override));
};

TEST(BulkheadManagerTest, DefaultConfiguration) {
    GatewayBulkheadConfig cfg;
    EXPECT_EQ(cfg.auth_max_concurrent, 100u);
    EXPECT_EQ(cfg.messaging_max_concurrent, 200u);
    EXPECT_EQ(cfg.files_max_concurrent, 50u);
    EXPECT_EQ(cfg.emergency_reserved_slots, 10u);

    BulkheadManager manager(cfg);
    EXPECT_EQ(manager.active_count(WorkloadCategory::Auth), 0u);
    EXPECT_EQ(manager.available_slots(WorkloadCategory::Auth), 100u);
    EXPECT_EQ(manager.max_concurrent(WorkloadCategory::Auth), 100u);

    EXPECT_EQ(manager.active_count(WorkloadCategory::Messaging), 0u);
    EXPECT_EQ(manager.available_slots(WorkloadCategory::Messaging), 200u);

    EXPECT_EQ(manager.active_count(WorkloadCategory::Files), 0u);
    EXPECT_EQ(manager.available_slots(WorkloadCategory::Files), 50u);

    EXPECT_EQ(manager.active_count(WorkloadCategory::Emergency), 0u);
    EXPECT_EQ(manager.available_slots(WorkloadCategory::Emergency), 10u);
    EXPECT_EQ(manager.max_concurrent(WorkloadCategory::Emergency), 10u);
}

TEST(BulkheadManagerTest, WorkloadBulkheadAtomicAcquireAndRelease) {
    WorkloadBulkhead bulkhead(2);
    EXPECT_EQ(bulkhead.max_concurrent(), 2u);
    EXPECT_EQ(bulkhead.active_count(), 0u);
    EXPECT_EQ(bulkhead.available_slots(), 2u);

    EXPECT_TRUE(bulkhead.try_acquire());
    EXPECT_EQ(bulkhead.active_count(), 1u);
    EXPECT_EQ(bulkhead.available_slots(), 1u);

    EXPECT_TRUE(bulkhead.try_acquire());
    EXPECT_EQ(bulkhead.active_count(), 2u);
    EXPECT_EQ(bulkhead.available_slots(), 0u);

    // Pool saturated
    EXPECT_FALSE(bulkhead.try_acquire());
    EXPECT_EQ(bulkhead.active_count(), 2u);

    // Release 1 slot
    bulkhead.release();
    EXPECT_EQ(bulkhead.active_count(), 1u);
    EXPECT_EQ(bulkhead.available_slots(), 1u);

    // Now acquisition succeeds again
    EXPECT_TRUE(bulkhead.try_acquire());
    EXPECT_EQ(bulkhead.active_count(), 2u);

    // Clean release
    bulkhead.release();
    bulkhead.release();
    EXPECT_EQ(bulkhead.active_count(), 0u);

    // Underflow protection
    bulkhead.release();
    EXPECT_EQ(bulkhead.active_count(), 0u);
}

TEST(BulkheadManagerTest, BulkheadLeaseRaii) {
    WorkloadBulkhead bulkhead(2);

    {
        BulkheadLease lease(&bulkhead, WorkloadCategory::Auth, bulkhead.try_acquire());
        EXPECT_TRUE(lease.is_acquired());
        EXPECT_TRUE(static_cast<bool>(lease));
        EXPECT_EQ(lease.category(), WorkloadCategory::Auth);
        EXPECT_EQ(bulkhead.active_count(), 1u);
    }
    // Slot released on scope exit
    EXPECT_EQ(bulkhead.active_count(), 0u);

    // Explicit manual release
    {
        BulkheadLease lease(&bulkhead, WorkloadCategory::Messaging, bulkhead.try_acquire());
        EXPECT_TRUE(lease);
        EXPECT_EQ(bulkhead.active_count(), 1u);

        lease.release();
        EXPECT_FALSE(lease.is_acquired());
        EXPECT_FALSE(static_cast<bool>(lease));
        EXPECT_EQ(bulkhead.active_count(), 0u);

        // Destructor should not double-release
    }
    EXPECT_EQ(bulkhead.active_count(), 0u);

    // Move semantics
    {
        BulkheadLease lease1(&bulkhead, WorkloadCategory::Files, bulkhead.try_acquire());
        EXPECT_TRUE(lease1);
        EXPECT_EQ(bulkhead.active_count(), 1u);

        BulkheadLease lease2 = std::move(lease1);
        EXPECT_FALSE(lease1);
        EXPECT_TRUE(lease2);
        EXPECT_EQ(lease2.category(), WorkloadCategory::Files);
        EXPECT_EQ(bulkhead.active_count(), 1u);

        BulkheadLease lease3;
        lease3 = std::move(lease2);
        EXPECT_FALSE(lease2);
        EXPECT_TRUE(lease3);
        EXPECT_EQ(bulkhead.active_count(), 1u);
    }
    EXPECT_EQ(bulkhead.active_count(), 0u);
}

TEST(BulkheadManagerTest, WorkloadIsolationNoisyNeighbor) {
    GatewayBulkheadConfig cfg;
    cfg.auth_max_concurrent = 2;
    cfg.messaging_max_concurrent = 2;
    cfg.files_max_concurrent = 2;
    cfg.emergency_reserved_slots = 2;

    BulkheadManager manager(cfg);

    // 1. Completely saturate Files pool
    auto file_lease1 = manager.acquire(WorkloadCategory::Files);
    auto file_lease2 = manager.acquire(WorkloadCategory::Files);
    EXPECT_TRUE(file_lease1);
    EXPECT_TRUE(file_lease2);
    EXPECT_EQ(manager.active_count(WorkloadCategory::Files), 2u);

    // 3rd Files request must be rejected
    auto file_lease3 = manager.acquire(WorkloadCategory::Files);
    EXPECT_FALSE(file_lease3);

    // 2. Auth, Messaging, and Emergency pools MUST NOT be starved or affected
    auto auth_lease = manager.acquire(WorkloadCategory::Auth);
    EXPECT_TRUE(auth_lease);
    EXPECT_EQ(manager.active_count(WorkloadCategory::Auth), 1u);

    auto msg_lease = manager.acquire(WorkloadCategory::Messaging);
    EXPECT_TRUE(msg_lease);
    EXPECT_EQ(manager.active_count(WorkloadCategory::Messaging), 1u);

    auto emg_lease = manager.acquire(WorkloadCategory::Emergency);
    EXPECT_TRUE(emg_lease);
    EXPECT_EQ(manager.active_count(WorkloadCategory::Emergency), 1u);

    // 3. Release one Files lease -> next Files acquisition succeeds
    file_lease1.release();
    EXPECT_EQ(manager.active_count(WorkloadCategory::Files), 1u);

    auto file_lease4 = manager.acquire(WorkloadCategory::Files);
    EXPECT_TRUE(file_lease4);
    EXPECT_EQ(manager.active_count(WorkloadCategory::Files), 2u);
}

TEST(BulkheadManagerTest, ClassifyPath) {
    EXPECT_EQ(BulkheadManager::classify_path("/health/live"), WorkloadCategory::Emergency);
    EXPECT_EQ(BulkheadManager::classify_path("/health/ready"), WorkloadCategory::Emergency);

    EXPECT_EQ(BulkheadManager::classify_path("/api/v1/auth/login"), WorkloadCategory::Auth);
    EXPECT_EQ(BulkheadManager::classify_path("/api/v1/auth/refresh"), WorkloadCategory::Auth);
    EXPECT_EQ(BulkheadManager::classify_path("/api/v1/users/me"), WorkloadCategory::Auth);
    EXPECT_EQ(BulkheadManager::classify_path("/api/v1/devices"), WorkloadCategory::Auth);

    EXPECT_EQ(BulkheadManager::classify_path("/api/v1/messages/send"), WorkloadCategory::Messaging);
    EXPECT_EQ(BulkheadManager::classify_path("/api/v1/messages/inbox"), WorkloadCategory::Messaging);

    EXPECT_EQ(BulkheadManager::classify_path("/api/v1/files/upload"), WorkloadCategory::Files);
    EXPECT_EQ(BulkheadManager::classify_path("/api/v1/files/download"), WorkloadCategory::Files);

    EXPECT_EQ(to_string(WorkloadCategory::Auth), "Auth");
    EXPECT_EQ(to_string(WorkloadCategory::Messaging), "Messaging");
    EXPECT_EQ(to_string(WorkloadCategory::Files), "Files");
    EXPECT_EQ(to_string(WorkloadCategory::Emergency), "Emergency");
}

TEST(BulkheadManagerTest, WriteRejectionRfc7807) {
    httplib::Response res;
    BulkheadManager::write_rejection(res, "test-req-999", 5);

    EXPECT_EQ(res.status, 503);
    EXPECT_TRUE(res.has_header("Retry-After"));
    EXPECT_EQ(res.get_header_value("Retry-After"), "5");

    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["status"], 503);
    EXPECT_EQ(json["type"], "https://securecloud.internal/errors/bulkhead-limit-exceeded");
    EXPECT_EQ(json["title"], "Service Unavailable");
    EXPECT_EQ(json["request_id"], "test-req-999");
    EXPECT_EQ(json["error"]["code"], "BULKHEAD_LIMIT_EXCEEDED");
    EXPECT_EQ(json["error"]["request_id"], "test-req-999");
}

TEST(BulkheadManagerTest, ConcurrencyStressTest) {
    constexpr uint32_t k_max_concurrency = 4;
    constexpr int k_num_threads = 16;
    constexpr int k_iterations_per_thread = 50;

    GatewayBulkheadConfig cfg;
    cfg.auth_max_concurrent = k_max_concurrency;
    BulkheadManager manager(cfg);

    std::atomic<bool> start_signal{false};
    std::atomic<uint32_t> max_observed_active{0};
    std::atomic<uint32_t> total_acquired{0};
    std::atomic<uint32_t> total_rejected{0};

    std::vector<std::thread> workers;
    workers.reserve(k_num_threads);

    for (int t = 0; t < k_num_threads; ++t) {
        workers.emplace_back([&] {
            while (!start_signal.load(std::memory_order_relaxed)) {
                std::this_thread::yield();
            }

            for (int i = 0; i < k_iterations_per_thread; ++i) {
                auto lease = manager.acquire(WorkloadCategory::Auth);
                if (lease) {
                    total_acquired.fetch_add(1, std::memory_order_relaxed);
                    uint32_t current_active = manager.active_count(WorkloadCategory::Auth);

                    // Track maximum observed active concurrency
                    uint32_t cur_max = max_observed_active.load(std::memory_order_relaxed);
                    while (current_active > cur_max && !max_observed_active.compare_exchange_weak(
                                                           cur_max, current_active, std::memory_order_relaxed)) {
                    }

                    // Simulate slight work while holding lease to induce thread contention
                    std::this_thread::sleep_for(std::chrono::microseconds(50));
                } else {
                    total_rejected.fetch_add(1, std::memory_order_relaxed);
                    std::this_thread::yield();
                }
            }
        });
    }

    start_signal.store(true, std::memory_order_release);
    for (auto& th : workers) {
        th.join();
    }

    // Invariants
    EXPECT_LE(max_observed_active.load(), k_max_concurrency);
    EXPECT_EQ(manager.active_count(WorkloadCategory::Auth), 0u);
    EXPECT_EQ(manager.available_slots(WorkloadCategory::Auth), k_max_concurrency);
    EXPECT_GT(total_acquired.load(), 0u);
    EXPECT_GT(total_rejected.load(), 0u);
}

TEST(BulkheadManagerTest, AuthProxyHandlerSaturatedRejection) {
    auto mock_auth = std::make_shared<MockAuthClient>();
    auto deadline_mgr = std::make_shared<DeadlineManager>();
    auto retry_policy = std::make_shared<RetryPolicy>();

    GatewayBulkheadConfig cfg;
    cfg.auth_max_concurrent = 1;
    auto bulkhead_mgr = std::make_shared<BulkheadManager>(cfg);

    AuthProxyHandler handler(mock_auth, deadline_mgr, retry_policy, bulkhead_mgr);

    // Manually hold the only slot in the Auth pool
    auto holding_lease = bulkhead_mgr->acquire(WorkloadCategory::Auth);
    ASSERT_TRUE(holding_lease);
    EXPECT_EQ(bulkhead_mgr->active_count(WorkloadCategory::Auth), 1u);

    // Now invoke handle_login while pool is saturated
    httplib::Request req;
    req.path = "/api/v1/auth/login";
    req.body = R"({"identifier":"user1","credential":"pwd"})";
    req.set_header("X-Request-ID", "corr-bulkhead-test");

    httplib::Response res;
    handler.handle_login(req, res);

    // Must be rejected with 503, BULKHEAD_LIMIT_EXCEEDED, and Retry-After: 5
    EXPECT_EQ(res.status, 503);
    EXPECT_TRUE(res.has_header("Retry-After"));
    EXPECT_EQ(res.get_header_value("Retry-After"), "5");

    auto json = nlohmann::json::parse(res.body);
    EXPECT_EQ(json["error"]["code"], "BULKHEAD_LIMIT_EXCEEDED");
    EXPECT_EQ(json["request_id"], "corr-bulkhead-test");

    // Release holding lease
    holding_lease.release();
    EXPECT_EQ(bulkhead_mgr->active_count(WorkloadCategory::Auth), 0u);

    // Mock successful authentication
    securecloud::auth::v1::AuthenticateResponse auth_proto_res;
    auth_proto_res.set_session_id("sess-1");
    auth_proto_res.set_access_token("token-1");
    auth_proto_res.set_user_id("user-1");
    EXPECT_CALL(*mock_auth, authenticate(_, _))
        .WillOnce(
            Return(securecloud::gateway::grpc::Result<securecloud::auth::v1::AuthenticateResponse>(auth_proto_res)));

    httplib::Response res2;
    handler.handle_login(req, res2);
    EXPECT_EQ(res2.status, 200);

    // Slot is released after handle_login completes
    EXPECT_EQ(bulkhead_mgr->active_count(WorkloadCategory::Auth), 0u);
}

TEST(BulkheadManagerTest, RouteRegistrarFilesBulkheadRejection) {
    auto mock_auth = std::make_shared<MockAuthClient>();
    common::health::HealthStatusManager health_manager("gateway-test");
    health_manager.set_live(true);
    health_manager.set_ready(true);

    GatewayBulkheadConfig cfg;
    cfg.files_max_concurrent = 1;
    cfg.emergency_reserved_slots = 5;
    auto bulkhead_mgr = std::make_shared<BulkheadManager>(cfg);

    auto auth_proxy = std::make_shared<AuthProxyHandler>(mock_auth, nullptr, nullptr, bulkhead_mgr);
    GatewayRouteRegistrar registrar(auth_proxy, health_manager, bulkhead_mgr);

    Router router;
    registrar.register_all_routes(router);

    // Establish authenticated context for protected route
    AuthenticatedContext auth_ctx("user-bulkhead-uuid", "dev-1", "sess-1",
                                  securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, {},
                                  2000000000000LL);
    RequestContext req_ctx("files-req-1", "127.0.0.1", 1700000000000LL, auth_ctx);
    ScopedRequestContext scope_guard(req_ctx);

    // Saturate Files bulkhead
    auto file_lease = bulkhead_mgr->acquire(WorkloadCategory::Files);
    ASSERT_TRUE(file_lease);

    // Files route request
    httplib::Request file_req;
    file_req.method = "POST";
    file_req.path = "/api/v1/files/upload";
    file_req.set_header("X-Request-ID", "files-req-1");

    httplib::Response file_res;
    router.handle(file_req, file_res);

    EXPECT_EQ(file_res.status, 503);
    EXPECT_TRUE(file_res.has_header("Retry-After"));
    auto file_json = nlohmann::json::parse(file_res.body);
    EXPECT_EQ(file_json["error"]["code"], "BULKHEAD_LIMIT_EXCEEDED");

    // Emergency (health) route request must succeed concurrently without starvation!
    httplib::Request health_req;
    health_req.method = "GET";
    health_req.path = "/health/live";

    httplib::Response health_res;
    router.handle(health_req, health_res);
    EXPECT_EQ(health_res.status, 200);
    EXPECT_EQ(health_res.body, R"({"status":"SERVING"})");
}

} // namespace
} // namespace securecloud::gateway::http
