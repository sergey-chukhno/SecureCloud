#include "gateway_config.hpp"
#include "http/https_server.hpp"
#include "http/logging_middleware.hpp"
#include "http/request_id_middleware.hpp"
#include "http/resource_limiter_middleware.hpp"
#include "http/router.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <future>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <openssl/ssl.h>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::gateway {
namespace {

constexpr int k_http_status_ok = 200;
constexpr int k_http_status_payload_too_large = 413;
constexpr int k_http_status_request_header_fields_too_large = 431;
constexpr int k_http_status_service_unavailable = 503;

constexpr uint16_t k_ephemeral_port = 0;
constexpr size_t k_default_header_limit_bytes = 16384;
constexpr size_t k_default_body_limit_bytes = 1048576;
constexpr size_t k_default_concurrency_limit = 1024;
constexpr size_t k_tight_header_limit_bytes = 2048;
constexpr size_t k_tight_body_limit_bytes = 8192;
constexpr size_t k_oversized_header_bytes = 5000;
constexpr size_t k_oversized_body_bytes = 32768;
constexpr size_t k_tight_concurrency_limit = 2;
constexpr uint32_t k_test_server_threads = 8;
constexpr int k_concurrent_clients_count = 10;
constexpr int k_burst_requests_per_client = 10;

constexpr auto k_server_req_timeout = std::chrono::milliseconds(5000);
constexpr auto k_client_timeout = std::chrono::milliseconds(4000);
constexpr auto k_barrier_wait_timeout = std::chrono::milliseconds(5000);
constexpr auto k_churn_sleep_duration = std::chrono::milliseconds(50);
constexpr auto k_poll_interval = std::chrono::milliseconds(10);
constexpr const char* k_loopback_address = "127.0.0.1";
constexpr const char* k_hsts_expected = "max-age=31536000; includeSubDomains; preload";

#ifdef _WIN32
inline void ensure_integration_winsock() noexcept {
    static const bool initialized = []() noexcept {
        WSADATA wsa{};
        return ::WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
    }();
    (void)initialized;
}
#else
inline void ensure_integration_winsock() noexcept {}
#endif

std::filesystem::path find_pki_dir() {
#ifdef SECURECLOUD_DEV_PKI_DIR
    std::filesystem::path p(SECURECLOUD_DEV_PKI_DIR);
    if (std::filesystem::exists(p / "ca" / "ca.crt")) {
        return p;
    }
#endif
    auto curr = std::filesystem::current_path();
    while (!curr.empty() && curr != curr.root_path()) {
        if (std::filesystem::exists(curr / "deploy" / "dev-pki" / "ca" / "ca.crt")) {
            return curr / "deploy" / "dev-pki";
        }
        curr = curr.parent_path();
    }
    return "deploy/dev-pki";
}

GatewayConfig make_integration_gateway_config(size_t max_header_bytes = k_default_header_limit_bytes,
                                              size_t max_body_bytes = k_default_body_limit_bytes,
                                              size_t max_concurrent = k_default_concurrency_limit) {
    ensure_integration_winsock();
    auto pki_root = find_pki_dir();

    GatewayConfig cfg;
    cfg.http_listen_address = k_loopback_address;
    cfg.http_listen_port = k_ephemeral_port;
    cfg.server_threads = k_test_server_threads;
    cfg.request_timeout_ms = k_server_req_timeout;

    cfg.tls.enabled = true;
    cfg.tls.cert_path = (pki_root / "services" / "gateway" / "gateway.crt").string();
    cfg.tls.key_path = (pki_root / "services" / "gateway" / "gateway.key").string();
    cfg.tls.ca_chain_path = (pki_root / "ca" / "ca.crt").string();
    cfg.tls.https_listen_port = k_ephemeral_port;
    cfg.tls.min_tls_version = "TLSv1.3";
    cfg.tls.cipher_suites = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";

    cfg.limits.max_header_bytes = max_header_bytes;
    cfg.limits.max_body_bytes = max_body_bytes;
    cfg.limits.max_concurrent_connections = max_concurrent;
    cfg.max_payload_bytes = k_default_body_limit_bytes;

    return cfg;
}

std::unique_ptr<httplib::SSLClient> create_ssl_client(uint16_t port, const std::string& ca_path,
                                                      bool verify_cert = true) {
    auto client = std::make_unique<httplib::SSLClient>(k_loopback_address, port);
    if (!ca_path.empty()) {
        client->set_ca_cert_path(ca_path);
    }
    client->enable_server_certificate_verification(verify_cert);
    client->enable_server_hostname_verification(false);
    client->set_connection_timeout(k_client_timeout);
    client->set_read_timeout(k_client_timeout);
    client->set_write_timeout(k_client_timeout);
    return client;
}

void register_standard_health_routes(http::Router& router) {
    router.get("/health/live", [](const httplib::Request&, httplib::Response& res) {
        res.status = k_http_status_ok;
        res.set_content(R"({"status":"SERVING"})", "application/json");
    });

    router.get("/health/ready", [](const httplib::Request&, httplib::Response& res) {
        res.status = k_http_status_ok;
        res.set_content(R"({"status":"SERVING"})", "application/json");
    });
}

std::string check_problem_details(const httplib::Result& res, int expected_status, const std::string& expected_title) {
    if (!res) {
        return "Result is null";
    }
    if (res->status != expected_status) {
        return "Unexpected status: " + std::to_string(res->status);
    }
    if (res->get_header_value("Content-Type") != "application/problem+json") {
        return "Unexpected Content-Type: " + res->get_header_value("Content-Type");
    }
    auto json_body = nlohmann::json::parse(res->body, nullptr, false);
    if (json_body.is_discarded()) {
        return "Invalid JSON body";
    }
    if (json_body.value("status", -1) != expected_status) {
        return "JSON status mismatch";
    }
    if (json_body.value("title", "") != expected_title) {
        return "JSON title mismatch";
    }
    if (!json_body.contains("request_id")) {
        return "Missing request_id";
    }
    return "";
}

void register_concurrency_gate_route(http::Router& router, std::atomic<int>& active_in_flight,
                                     const std::shared_future<void>& barrier_future) {
    router.get("/test/concurrency_gate",
               [&active_in_flight, barrier_future](const httplib::Request&, httplib::Response& res) {
                   ++active_in_flight;
                   barrier_future.wait_for(k_barrier_wait_timeout);
                   --active_in_flight;
                   res.status = k_http_status_ok;
                   res.set_content("gate_open", "text/plain");
               });
}

std::vector<std::thread> spawn_concurrency_fillers(uint16_t port, const std::string& ca_file,
                                                   std::vector<int>& worker_results,
                                                   const std::atomic<int>& active_in_flight) {
    std::vector<std::thread> workers;
    workers.reserve(k_tight_concurrency_limit);
    for (size_t i = 0; i < k_tight_concurrency_limit; ++i) {
        workers.emplace_back([port, &ca_file, &worker_results, i] {
            try {
                auto client = create_ssl_client(port, ca_file);
                auto res = client->Get("/test/concurrency_gate");
                worker_results[i] = res ? res->status : -1;
            } catch (...) {
                worker_results[i] = -1;
            }
        });
    }

    while (active_in_flight.load() < static_cast<int>(k_tight_concurrency_limit)) {
        std::this_thread::sleep_for(k_poll_interval);
    }
    return workers;
}

void release_and_join_workers(std::vector<std::thread>& workers, const std::vector<int>& worker_results,
                              std::promise<void>& release_barrier) {
    release_barrier.set_value();
    for (auto& th : workers) {
        if (th.joinable()) {
            th.join();
        }
    }
    for (int status : worker_results) {
        EXPECT_EQ(status, k_http_status_ok);
    }
}

} // namespace

// ============================================================================
// GW-002-T06: End-to-End Gateway HTTPS Security & Handshake Integration Tests
// ============================================================================

TEST(GatewayHttpsIntegrationTest, SuccessfulTls13HandshakeAndHealthQuery) {
    auto config = make_integration_gateway_config();
    http::Router router;
    router.use(std::make_shared<http::ResourceLimiterMiddleware>(config));
    register_standard_health_routes(router);

    http::HttpsServer server(config);
    router.register_into(server);
    ASSERT_TRUE(server.start_async());
    uint16_t port = server.bound_port();
    ASSERT_GT(port, 0);

    auto ca_file = (find_pki_dir() / "ca" / "ca.crt").string();
    auto client = create_ssl_client(port, ca_file);

    // 1. Query /health/live
    auto live_res = client->Get("/health/live");
    ASSERT_TRUE(live_res) << "HTTPS GET /health/live failed";
    EXPECT_EQ(live_res->status, k_http_status_ok);
    EXPECT_EQ(live_res->get_header_value("Content-Type"), "application/json");
    EXPECT_EQ(live_res->get_header_value("Strict-Transport-Security"), k_hsts_expected);
    EXPECT_TRUE(live_res->has_header("X-Request-Id"));

    auto live_json = nlohmann::json::parse(live_res->body, nullptr, false);
    ASSERT_FALSE(live_json.is_discarded());
    EXPECT_EQ(live_json["status"], "SERVING");

    // 2. Query /health/ready
    auto ready_res = client->Get("/health/ready");
    ASSERT_TRUE(ready_res) << "HTTPS GET /health/ready failed";
    EXPECT_EQ(ready_res->status, k_http_status_ok);
    auto ready_json = nlohmann::json::parse(ready_res->body, nullptr, false);
    ASSERT_FALSE(ready_json.is_discarded());
    EXPECT_EQ(ready_json["status"], "SERVING");

    server.stop();
}

TEST(GatewayHttpsIntegrationTest, UntrustedRootCaHandshakeFailsClosed) {
    auto config = make_integration_gateway_config();
    http::Router router;
    register_standard_health_routes(router);

    http::HttpsServer server(config);
    router.register_into(server);
    ASSERT_TRUE(server.start_async());
    uint16_t port = server.bound_port();
    ASSERT_GT(port, 0);

    // Configure client with an untrusted or non-existent CA path while enforcing verification
    std::string invalid_ca_path = (find_pki_dir() / "services" / "gateway" / "gateway.crt").string();
    auto client = create_ssl_client(port, invalid_ca_path, true);

    auto res = client->Get("/health/live");
    EXPECT_FALSE(res) << "Connection with untrusted CA must fail closed at the TLS handshake";

    server.stop();
}

TEST(GatewayHttpsIntegrationTest, OversizedHeaderRejectedWithHttp431) {
    auto config = make_integration_gateway_config(k_tight_header_limit_bytes, k_default_body_limit_bytes,
                                                  k_default_concurrency_limit);
    http::Router router;
    router.use(std::make_shared<http::ResourceLimiterMiddleware>(config));
    register_standard_health_routes(router);

    http::HttpsServer server(config);
    router.register_into(server);
    ASSERT_TRUE(server.start_async());
    uint16_t port = server.bound_port();
    ASSERT_GT(port, 0);

    auto ca_file = (find_pki_dir() / "ca" / "ca.crt").string();
    auto client = create_ssl_client(port, ca_file);

    std::string oversized_header_value(k_oversized_header_bytes, 'H');
    httplib::Headers headers = {{"X-Oversized-Header", oversized_header_value}};

    auto res = client->Get("/health/live", headers);
    EXPECT_EQ(
        check_problem_details(res, k_http_status_request_header_fields_too_large, "Request Header Fields Too Large"),
        "");

    server.stop();
}

TEST(GatewayHttpsIntegrationTest, OversizedPayloadRejectedWithHttp413) {
    auto config = make_integration_gateway_config(k_default_header_limit_bytes, k_tight_body_limit_bytes,
                                                  k_default_concurrency_limit);
    http::Router router;
    router.use(std::make_shared<http::ResourceLimiterMiddleware>(config));
    router.post("/api/v1/upload", [](const httplib::Request&, httplib::Response& res) {
        res.status = k_http_status_ok;
        res.set_content("ok", "text/plain");
    });

    http::HttpsServer server(config);
    router.register_into(server);
    ASSERT_TRUE(server.start_async());
    uint16_t port = server.bound_port();
    ASSERT_GT(port, 0);

    auto ca_file = (find_pki_dir() / "ca" / "ca.crt").string();
    auto client = create_ssl_client(port, ca_file);

    std::string oversized_body(k_oversized_body_bytes, 'B');
    auto res = client->Post("/api/v1/upload", oversized_body, "application/octet-stream");
    EXPECT_EQ(check_problem_details(res, k_http_status_payload_too_large, "Payload Too Large"), "");

    server.stop();
}

TEST(GatewayHttpsIntegrationTest, ActiveConcurrencyLimitEnforcesHttp503WithRetryAfter) {
    auto config = make_integration_gateway_config(k_default_header_limit_bytes, k_default_body_limit_bytes,
                                                  k_tight_concurrency_limit);
    http::Router router;
    router.use(std::make_shared<http::ResourceLimiterMiddleware>(config));

    std::atomic<int> active_in_flight{0};
    std::promise<void> release_barrier;
    register_concurrency_gate_route(router, active_in_flight, release_barrier.get_future().share());

    http::HttpsServer server(config);
    router.register_into(server);
    ASSERT_TRUE(server.start_async());
    uint16_t port = server.bound_port();
    ASSERT_GT(port, 0);

    auto ca_file = (find_pki_dir() / "ca" / "ca.crt").string();
    std::vector<int> worker_results(k_tight_concurrency_limit, 0);
    auto workers = spawn_concurrency_fillers(port, ca_file, worker_results, active_in_flight);

    auto client = create_ssl_client(port, ca_file);
    auto reject_res = client->Get("/test/concurrency_gate");
    EXPECT_EQ(check_problem_details(reject_res, k_http_status_service_unavailable, "Service Unavailable"), "");
    EXPECT_EQ(reject_res->get_header_value("Retry-After"), "5");

    release_and_join_workers(workers, worker_results, release_barrier);
    server.stop();
}

TEST(GatewayHttpsIntegrationTest, ConcurrentLoadAndGracefulTeardown) {
    auto config = make_integration_gateway_config();
    http::Router router;
    router.use(std::make_shared<http::ResourceLimiterMiddleware>(config));
    register_standard_health_routes(router);

    http::HttpsServer server(config);
    router.register_into(server);
    ASSERT_TRUE(server.start_async());
    uint16_t port = server.bound_port();
    ASSERT_GT(port, 0);

    auto ca_file = (find_pki_dir() / "ca" / "ca.crt").string();
    std::atomic<bool> run_flag{true};
    std::atomic<int> completed_queries{0};
    std::atomic<int> failed_queries{0};

    std::vector<std::thread> threads;
    threads.reserve(k_concurrent_clients_count);

    for (int i = 0; i < k_concurrent_clients_count; ++i) {
        threads.emplace_back([port, &ca_file, &run_flag, &completed_queries, &failed_queries] {
            try {
                auto client = create_ssl_client(port, ca_file);
                for (int req = 0; req < k_burst_requests_per_client && run_flag.load(); ++req) {
                    auto res = client->Get("/health/live");
                    if (res && res->status == k_http_status_ok) {
                        ++completed_queries;
                    }
                }
            } catch (...) {
                ++failed_queries;
            }
        });
    }

    std::this_thread::sleep_for(k_churn_sleep_duration);

    run_flag.store(false);
    server.stop();

    for (auto& th : threads) {
        if (th.joinable()) {
            th.join();
        }
    }

    EXPECT_GT(completed_queries.load(), 0);
    EXPECT_FALSE(server.is_running());
    EXPECT_EQ(server.state(), http::ServerState::Stopped);
}

} // namespace securecloud::gateway
