#include "http/http_server.hpp"

#include <chrono>
#include <cstdint>
#include <future>
#include <gtest/gtest.h>
#include <httplib.h>
#include <string>
#include <vector>

namespace securecloud::gateway::http {
namespace {

constexpr uint16_t k_ephemeral_port = 0;
constexpr uint32_t k_test_server_threads = 4;
constexpr uint64_t k_test_max_payload_bytes = 1048576;
constexpr auto k_test_timeout = std::chrono::milliseconds(2000);
constexpr auto k_client_timeout = std::chrono::milliseconds(1000);
constexpr auto k_short_probe_timeout = std::chrono::milliseconds(200);
constexpr int k_http_status_ok = 200;
constexpr int k_concurrent_requests_count = 10;
constexpr const char* k_loopback_address = "127.0.0.1";

void verify_health_endpoint(uint16_t port) {
    httplib::Client client(k_loopback_address, port);
    client.set_connection_timeout(k_client_timeout);
    client.set_read_timeout(k_client_timeout);

    auto res = client.Get("/health");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_ok);
    EXPECT_EQ(res->body, R"({"status":"ok"})");
}

TEST(HttpServerLifecycleTest, InitialStateIsStopped) {
    HttpServer server(k_loopback_address, k_ephemeral_port, k_test_server_threads, k_test_max_payload_bytes,
                      k_test_timeout);

    EXPECT_EQ(server.state(), ServerState::Stopped);
    EXPECT_FALSE(server.is_running());
    EXPECT_EQ(server.bound_port(), 0);
    EXPECT_EQ(server.listen_address(), k_loopback_address);
}

TEST(HttpServerLifecycleTest, StartsAsyncAndBindsEphemeralPort) {
    HttpServer server(k_loopback_address, k_ephemeral_port, k_test_server_threads, k_test_max_payload_bytes,
                      k_test_timeout);

    server.get("/health", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    ASSERT_TRUE(server.start_async());
    EXPECT_EQ(server.state(), ServerState::Running);
    EXPECT_TRUE(server.is_running());

    uint16_t port = server.bound_port();
    EXPECT_GT(port, 0);

    verify_health_endpoint(port);

    server.stop();
    EXPECT_EQ(server.state(), ServerState::Stopped);
    EXPECT_FALSE(server.is_running());
}

TEST(HttpServerLifecycleTest, ServesConcurrentRequestsWithThreadPool) {
    HttpServer server(k_loopback_address, k_ephemeral_port, k_test_server_threads, k_test_max_payload_bytes,
                      k_test_timeout);

    server.get("/ping", [](const httplib::Request&, httplib::Response& res) { res.set_content("pong", "text/plain"); });

    ASSERT_TRUE(server.start_async());
    uint16_t port = server.bound_port();
    ASSERT_GT(port, 0);

    std::vector<std::future<bool>> futures;
    futures.reserve(k_concurrent_requests_count);

    for (int i = 0; i < k_concurrent_requests_count; ++i) {
        futures.push_back(std::async(std::launch::async, [port] {
            httplib::Client client(k_loopback_address, port);
            client.set_connection_timeout(k_client_timeout);
            client.set_read_timeout(k_client_timeout);
            auto res = client.Get("/ping");
            return res && res->status == k_http_status_ok && res->body == "pong";
        }));
    }

    for (auto& f : futures) {
        EXPECT_TRUE(f.get());
    }

    server.stop();
}

TEST(HttpServerLifecycleTest, GracefulShutdownRejectsSubsequentRequests) {
    HttpServer server(k_loopback_address, k_ephemeral_port, k_test_server_threads, k_test_max_payload_bytes,
                      k_test_timeout);

    server.get("/test", [](const httplib::Request&, httplib::Response& res) { res.set_content("ok", "text/plain"); });

    ASSERT_TRUE(server.start_async());
    uint16_t port = server.bound_port();
    ASSERT_GT(port, 0);

    // Stop server
    server.stop();
    EXPECT_EQ(server.state(), ServerState::Stopped);
    EXPECT_FALSE(server.is_running());

    // Subsequent request should fail to connect
    httplib::Client client(k_loopback_address, port);
    client.set_connection_timeout(k_short_probe_timeout);
    client.set_read_timeout(k_short_probe_timeout);
    auto res = client.Get("/test");
    EXPECT_FALSE(res);
}

TEST(HttpServerLifecycleTest, StopIsIdempotent) {
    HttpServer server(k_loopback_address, k_ephemeral_port, k_test_server_threads, k_test_max_payload_bytes,
                      k_test_timeout);

    ASSERT_TRUE(server.start_async());
    EXPECT_TRUE(server.is_running());

    // Multiple stop calls should not throw, crash, or deadlock
    server.stop();
    EXPECT_EQ(server.state(), ServerState::Stopped);
    EXPECT_FALSE(server.is_running());

    server.stop();
    EXPECT_EQ(server.state(), ServerState::Stopped);
    EXPECT_FALSE(server.is_running());
}

TEST(HttpServerLifecycleTest, DestructorPerformsCleanTeardown) {
    uint16_t port = 0;
    {
        HttpServer server(k_loopback_address, k_ephemeral_port, k_test_server_threads, k_test_max_payload_bytes,
                          k_test_timeout);

        server.get("/ping",
                   [](const httplib::Request&, httplib::Response& res) { res.set_content("pong", "text/plain"); });

        ASSERT_TRUE(server.start_async());
        port = server.bound_port();
        ASSERT_GT(port, 0);
        // Exits scope without explicit server.stop()
    }

    // Server should have been stopped in destructor
    httplib::Client client(k_loopback_address, port);
    client.set_connection_timeout(k_short_probe_timeout);
    client.set_read_timeout(k_short_probe_timeout);
    auto res = client.Get("/ping");
    EXPECT_FALSE(res);
}

} // namespace
} // namespace securecloud::gateway::http
