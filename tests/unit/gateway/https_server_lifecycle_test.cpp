#include "gateway_config.hpp"
#include "http/https_server.hpp"
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

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <future>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <openssl/ssl.h>
#include <string>
#include <vector>

namespace securecloud::gateway::http {
namespace {

constexpr uint16_t k_ephemeral_port = 0;
constexpr uint32_t k_test_server_threads = 4;
constexpr uint64_t k_test_max_payload_bytes = 1048576;
constexpr auto k_test_timeout = std::chrono::milliseconds(2000);
constexpr auto k_client_timeout = std::chrono::milliseconds(2000);
constexpr auto k_short_probe_timeout = std::chrono::milliseconds(200);
constexpr int k_http_status_ok = 200;
constexpr int k_http_status_not_found = 404;
constexpr int k_concurrent_requests_count = 10;
constexpr const char* k_loopback_address = "127.0.0.1";

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

GatewayTlsConfig make_valid_tls_config() {
    auto pki_root = find_pki_dir();
    GatewayTlsConfig cfg;
    cfg.enabled = true;
    cfg.cert_path = (pki_root / "services" / "gateway" / "gateway.crt").string();
    cfg.key_path = (pki_root / "services" / "gateway" / "gateway.key").string();
    cfg.ca_chain_path = (pki_root / "ca" / "ca.crt").string();
    cfg.https_listen_port = k_ephemeral_port;
    cfg.min_tls_version = "TLSv1.3";
    cfg.cipher_suites = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
    return cfg;
}

std::unique_ptr<httplib::SSLClient> create_test_ssl_client(uint16_t port, const std::string& ca_path) {
    auto client = std::make_unique<httplib::SSLClient>(k_loopback_address, port);
    client->set_ca_cert_path(ca_path);
    client->enable_server_certificate_verification(true);
    client->enable_server_hostname_verification(false);
    client->set_connection_timeout(k_client_timeout);
    client->set_read_timeout(k_client_timeout);
    client->set_write_timeout(k_client_timeout);
    return client;
}

void verify_https_get(uint16_t port, const std::string& ca_path, const std::string& path,
                      const std::string& expected_body) {
    auto client = create_test_ssl_client(port, ca_path);
    auto res = client->Get(path);
    ASSERT_TRUE(res) << "HTTPS GET failed with error: " << static_cast<int>(res.error());
    EXPECT_EQ(res->status, k_http_status_ok);
    EXPECT_EQ(res->body, expected_body);
}

void verify_router_routes(uint16_t port, const std::string& ca_path) {
    auto client = create_test_ssl_client(port, ca_path);
    auto res_ok = client->Get("/api/v1/ping");
    ASSERT_TRUE(res_ok);
    EXPECT_EQ(res_ok->status, k_http_status_ok);
    EXPECT_EQ(res_ok->body, R"({"pong":true})");

    auto res_404 = client->Get("/api/v1/unknown");
    ASSERT_TRUE(res_404);
    EXPECT_EQ(res_404->status, k_http_status_not_found);
}

void verify_tls12_downgrade_rejected(uint16_t port) {
    SSL_CTX* client_ctx = SSL_CTX_new(TLS_client_method());
    ASSERT_NE(client_ctx, nullptr);
    SSL_CTX_set_min_proto_version(client_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(client_ctx, TLS1_2_VERSION);

#ifdef _WIN32
    SOCKET sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_NE(sock, INVALID_SOCKET);
#else
    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(sock, 0);
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, k_loopback_address, &addr.sin_addr);

    int conn_res = ::connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    ASSERT_EQ(conn_res, 0) << "TCP connection failed";

    SSL* ssl = SSL_new(client_ctx);
    ASSERT_NE(ssl, nullptr);
#ifdef _WIN32
    SSL_set_fd(ssl, static_cast<int>(sock));
#else
    SSL_set_fd(ssl, sock);
#endif

    int handshake_res = SSL_connect(ssl);
    EXPECT_LE(handshake_res, 0) << "TLS 1.2 handshake must be rejected by TLS 1.3 strict server";

    SSL_free(ssl);
#ifdef _WIN32
    ::closesocket(sock);
#else
    ::close(sock);
#endif
    SSL_CTX_free(client_ctx);
}

TEST(HttpsServerLifecycleTest, InitialStateIsStopped) {
    auto tls_cfg = make_valid_tls_config();
    HttpsServer server(k_loopback_address, k_ephemeral_port, tls_cfg, k_test_server_threads, k_test_max_payload_bytes,
                       k_test_timeout);

    EXPECT_EQ(server.state(), ServerState::Stopped);
    EXPECT_FALSE(server.is_running());
    EXPECT_EQ(server.bound_port(), 0);
    EXPECT_EQ(server.listen_address(), k_loopback_address);
}

TEST(HttpsServerLifecycleTest, FailClosedOnMissingCertificates) {
    GatewayTlsConfig bad_cfg;
    bad_cfg.enabled = true;
    bad_cfg.cert_path = "/nonexistent/path/gateway.crt";
    bad_cfg.key_path = "/nonexistent/path/gateway.key";
    bad_cfg.https_listen_port = k_ephemeral_port;

    HttpsServer server(k_loopback_address, k_ephemeral_port, bad_cfg, k_test_server_threads, k_test_max_payload_bytes,
                       k_test_timeout);

    EXPECT_FALSE(server.start_async());
    EXPECT_EQ(server.state(), ServerState::Stopped);
    EXPECT_FALSE(server.is_running());
    EXPECT_EQ(server.bound_port(), 0);
}

TEST(HttpsServerLifecycleTest, FailClosedOnMismatchedKeyCertificatePair) {
    auto pki_root = find_pki_dir();
    GatewayTlsConfig mismatched_cfg;
    mismatched_cfg.enabled = true;
    mismatched_cfg.cert_path = (pki_root / "services" / "gateway" / "gateway.crt").string();
    mismatched_cfg.key_path = (pki_root / "services" / "auth" / "auth.key").string();
    mismatched_cfg.https_listen_port = k_ephemeral_port;

    HttpsServer server(k_loopback_address, k_ephemeral_port, mismatched_cfg, k_test_server_threads,
                       k_test_max_payload_bytes, k_test_timeout);

    EXPECT_FALSE(server.start_async());
    EXPECT_EQ(server.state(), ServerState::Stopped);
    EXPECT_FALSE(server.is_running());
}

TEST(HttpsServerLifecycleTest, StartsAsyncAndServesHttpsGet) {
    auto tls_cfg = make_valid_tls_config();
    HttpsServer server(k_loopback_address, k_ephemeral_port, tls_cfg, k_test_server_threads, k_test_max_payload_bytes,
                       k_test_timeout);

    server.get("/health/live", [](const httplib::Request&, httplib::Response& res) {
        res.status = k_http_status_ok;
        res.set_content(R"({"status":"SERVING"})", "application/json");
    });

    ASSERT_TRUE(server.start_async());
    EXPECT_EQ(server.state(), ServerState::Running);
    EXPECT_TRUE(server.is_running());

    uint16_t port = server.bound_port();
    ASSERT_GT(port, 0);

    verify_https_get(port, tls_cfg.ca_chain_path, "/health/live", R"({"status":"SERVING"})");

    server.stop();
    EXPECT_EQ(server.state(), ServerState::Stopped);
    EXPECT_FALSE(server.is_running());
}

TEST(HttpsServerLifecycleTest, RouterIntegrationOverHttps) {
    auto tls_cfg = make_valid_tls_config();
    HttpsServer server(k_loopback_address, k_ephemeral_port, tls_cfg, k_test_server_threads, k_test_max_payload_bytes,
                       k_test_timeout);

    Router router;
    router.get("/api/v1/ping", [](const httplib::Request&, httplib::Response& res) {
        res.status = k_http_status_ok;
        res.set_content(R"({"pong":true})", "application/json");
    });
    router.register_into(server);

    ASSERT_TRUE(server.start_async());
    uint16_t port = server.bound_port();
    ASSERT_GT(port, 0);

    verify_router_routes(port, tls_cfg.ca_chain_path);

    server.stop();
}

TEST(HttpsServerLifecycleTest, ServesConcurrentHttpsRequestsWithThreadPool) {
    auto tls_cfg = make_valid_tls_config();
    HttpsServer server(k_loopback_address, k_ephemeral_port, tls_cfg, k_test_server_threads, k_test_max_payload_bytes,
                       k_test_timeout);

    server.get("/ping", [](const httplib::Request&, httplib::Response& res) {
        res.status = k_http_status_ok;
        res.set_content("pong", "text/plain");
    });

    ASSERT_TRUE(server.start_async());
    uint16_t port = server.bound_port();
    ASSERT_GT(port, 0);

    std::vector<std::future<bool>> futures;
    futures.reserve(k_concurrent_requests_count);

    for (int i = 0; i < k_concurrent_requests_count; ++i) {
        futures.push_back(std::async(std::launch::async, [port, ca_path = tls_cfg.ca_chain_path] {
            auto client = create_test_ssl_client(port, ca_path);
            auto res = client->Get("/ping");
            return res && res->status == k_http_status_ok && res->body == "pong";
        }));
    }

    for (auto& f : futures) {
        EXPECT_TRUE(f.get());
    }

    server.stop();
}

TEST(HttpsServerLifecycleTest, GracefulShutdownRejectsSubsequentRequests) {
    auto tls_cfg = make_valid_tls_config();
    HttpsServer server(k_loopback_address, k_ephemeral_port, tls_cfg, k_test_server_threads, k_test_max_payload_bytes,
                       k_test_timeout);

    server.get("/probe", [](const httplib::Request&, httplib::Response& res) {
        res.status = k_http_status_ok;
        res.set_content("alive", "text/plain");
    });

    ASSERT_TRUE(server.start_async());
    uint16_t port = server.bound_port();
    ASSERT_GT(port, 0);

    verify_https_get(port, tls_cfg.ca_chain_path, "/probe", "alive");

    server.stop();
    EXPECT_EQ(server.state(), ServerState::Stopped);
    EXPECT_FALSE(server.is_running());

    httplib::SSLClient probe_client(k_loopback_address, port);
    probe_client.set_ca_cert_path(tls_cfg.ca_chain_path);
    probe_client.enable_server_certificate_verification(false);
    probe_client.set_connection_timeout(k_short_probe_timeout);
    probe_client.set_read_timeout(k_short_probe_timeout);

    auto res_after = probe_client.Get("/probe");
    EXPECT_FALSE(res_after);
}

TEST(HttpsServerLifecycleTest, StrictTls13ClampingRejectsTls12Handshake) {
    auto tls_cfg = make_valid_tls_config();
    HttpsServer server(k_loopback_address, k_ephemeral_port, tls_cfg, k_test_server_threads, k_test_max_payload_bytes,
                       k_test_timeout);

    server.get("/secure", [](const httplib::Request&, httplib::Response& res) {
        res.status = k_http_status_ok;
        res.set_content("secure", "text/plain");
    });

    ASSERT_TRUE(server.start_async());
    uint16_t port = server.bound_port();
    ASSERT_GT(port, 0);

    verify_tls12_downgrade_rejected(port);

    server.stop();
}

} // namespace
} // namespace securecloud::gateway::http
