#include "gateway_config.hpp"
#include "http/http_redirect_server.hpp"
#include "http/https_server.hpp"
#include "tls/tls_handler.hpp"

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
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <string>

namespace securecloud::gateway::http {
namespace {

constexpr uint16_t k_ephemeral_port = 0;
constexpr uint16_t k_sample_https_port = 8443;
constexpr uint16_t k_standard_https_port = 443;
constexpr int k_http_status_ok = 200;
constexpr int k_http_status_permanent_redirect = 308;
constexpr auto k_client_timeout = std::chrono::milliseconds(2000);
constexpr const char* k_loopback_address = "127.0.0.1";
constexpr const char* k_hsts_expected = "max-age=31536000; includeSubDomains; preload";

struct SocketGuard {
#ifdef _WIN32
    SOCKET fd{INVALID_SOCKET};
    ~SocketGuard() {
        if (fd != INVALID_SOCKET) {
            closesocket(fd);
        }
    }
#else
    int fd{-1};
    ~SocketGuard() {
        if (fd >= 0) {
            ::close(fd);
        }
    }
#endif
};

struct SslCtxDeleter {
    void operator()(SSL_CTX* ctx) const noexcept {
        if (ctx != nullptr) {
            SSL_CTX_free(ctx);
        }
    }
};

struct SslDeleter {
    void operator()(SSL* ssl) const noexcept {
        if (ssl != nullptr) {
            SSL_free(ssl);
        }
    }
};

using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;
using SslPtr = std::unique_ptr<SSL, SslDeleter>;

struct HandshakeResult {
    bool connected{false};
    int ssl_error{SSL_ERROR_NONE};
    std::string negotiated_version;
};

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

SocketGuard connect_tcp(uint16_t port) {
    SocketGuard sg;
#ifdef _WIN32
    sg.fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sg.fd == INVALID_SOCKET) {
        return sg;
    }
#else
    sg.fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sg.fd < 0) {
        return sg;
    }
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, k_loopback_address, &addr.sin_addr);

    if (connect(sg.fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
#ifdef _WIN32
        closesocket(sg.fd);
        sg.fd = INVALID_SOCKET;
#else
        ::close(sg.fd);
        sg.fd = -1;
#endif
    }
    return sg;
}

HandshakeResult execute_tls_client_handshake(uint16_t port, SSL_CTX* client_ctx) {
    HandshakeResult result{};
    auto sock = connect_tcp(port);
#ifdef _WIN32
    if (sock.fd == INVALID_SOCKET) {
        return result;
    }
    auto raw_fd = static_cast<int>(sock.fd);
#else
    if (sock.fd < 0) {
        return result;
    }
    int raw_fd = sock.fd;
#endif

    SslPtr ssl(SSL_new(client_ctx));
    if (!ssl) {
        return result;
    }
    SSL_set_fd(ssl.get(), raw_fd);

    int rc = SSL_connect(ssl.get());
    if (rc == 1) {
        result.connected = true;
        const char* ver = SSL_get_version(ssl.get());
        if (ver != nullptr) {
            result.negotiated_version = ver;
        }
        SSL_shutdown(ssl.get());
    } else {
        result.connected = false;
        result.ssl_error = SSL_get_error(ssl.get(), rc);
    }
    return result;
}

} // namespace

// ============================================================================
// HttpRedirectServer Unit Tests
// ============================================================================

TEST(HttpRedirectServerTest, CleartextGetReturns308WithLocationAndHsts) {
    HttpRedirectServer server(k_loopback_address, k_ephemeral_port, k_sample_https_port);
    ASSERT_TRUE(server.start_async());
    uint16_t port = server.bound_port();
    ASSERT_GT(port, 0);

    httplib::Client client(k_loopback_address, port);
    client.set_follow_location(false);
    client.set_connection_timeout(k_client_timeout);
    client.set_read_timeout(k_client_timeout);

    auto res = client.Get("/api/v1/auth/login");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_permanent_redirect);
    EXPECT_EQ(res->get_header_value("Location"), "https://127.0.0.1:8443/api/v1/auth/login");
    EXPECT_EQ(res->get_header_value("Strict-Transport-Security"), k_hsts_expected);
    EXPECT_EQ(res->get_header_value("Connection"), "close");

    server.stop();
}

TEST(HttpRedirectServerTest, PreservesQueryParamsAndPostMethod) {
    HttpRedirectServer server(k_loopback_address, k_ephemeral_port, k_sample_https_port);
    ASSERT_TRUE(server.start_async());
    uint16_t port = server.bound_port();
    ASSERT_GT(port, 0);

    httplib::Client client(k_loopback_address, port);
    client.set_follow_location(false);
    client.set_connection_timeout(k_client_timeout);
    client.set_read_timeout(k_client_timeout);

    std::string path = "/api/v1/auth/token?grant_type=refresh&scope=read";
    auto res = client.Post(path, R"({"refresh_token":"sample"})", "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_permanent_redirect);
    EXPECT_EQ(res->get_header_value("Location"), "https://127.0.0.1:8443" + path);
    EXPECT_EQ(res->get_header_value("Strict-Transport-Security"), k_hsts_expected);

    server.stop();
}

TEST(HttpRedirectServerTest, NormalizesCustomHostHeader) {
    HttpRedirectServer server(k_loopback_address, k_ephemeral_port, k_sample_https_port);
    ASSERT_TRUE(server.start_async());
    uint16_t port = server.bound_port();
    ASSERT_GT(port, 0);

    httplib::Client client(k_loopback_address, port);
    client.set_follow_location(false);
    client.set_connection_timeout(k_client_timeout);
    client.set_read_timeout(k_client_timeout);

    httplib::Headers headers = {{"Host", "gateway.securecloud.io:8080"}};
    auto res = client.Get("/health", headers);
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_permanent_redirect);
    EXPECT_EQ(res->get_header_value("Location"), "https://gateway.securecloud.io:8443/health");

    server.stop();
}

TEST(HttpRedirectServerTest, StandardHttpsPortOmitsPortInLocation) {
    HttpRedirectServer server(k_loopback_address, k_ephemeral_port, k_standard_https_port);
    EXPECT_EQ(server.build_redirect_url("securecloud.io", "/api/ping"), "https://securecloud.io/api/ping");
    EXPECT_EQ(server.build_redirect_url("securecloud.io:8080", "/"), "https://securecloud.io/");
}

TEST(HttpRedirectServerTest, LifecycleAndStateTransitions) {
    HttpRedirectServer server(k_loopback_address, k_ephemeral_port, k_sample_https_port);
    EXPECT_FALSE(server.is_running());
    EXPECT_EQ(server.state(), ServerState::Stopped);

    ASSERT_TRUE(server.start_async());
    EXPECT_TRUE(server.is_running());
    EXPECT_EQ(server.state(), ServerState::Running);

    server.stop();
    EXPECT_FALSE(server.is_running());
    EXPECT_EQ(server.state(), ServerState::Stopped);
}

// ============================================================================
// TLS Downgrade Protection & Handshake Rejection Tests
// ============================================================================

TEST(DowngradeGuardTest, HttpsServerEmitsHstsHeaderOnResponses) {
    auto tls_cfg = make_valid_tls_config();
    HttpsServer server(k_loopback_address, k_ephemeral_port, tls_cfg);
    server.get("/ping", [](const httplib::Request&, httplib::Response& res) {
        res.status = k_http_status_ok;
        res.set_content("pong", "text/plain");
    });

    ASSERT_TRUE(server.start_async());
    uint16_t port = server.bound_port();
    ASSERT_GT(port, 0);

    auto pki_root = find_pki_dir();
    httplib::SSLClient client(k_loopback_address, port);
    client.set_ca_cert_path((pki_root / "ca" / "ca.crt").string());
    client.enable_server_certificate_verification(true);
    client.enable_server_hostname_verification(false);
    client.set_connection_timeout(k_client_timeout);
    client.set_read_timeout(k_client_timeout);

    auto res = client.Get("/ping");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, k_http_status_ok);
    EXPECT_EQ(res->get_header_value("Strict-Transport-Security"), k_hsts_expected);

    server.stop();
}

TEST(DowngradeGuardTest, Tls13NegotiationSucceeds) {
    auto tls_cfg = make_valid_tls_config();
    HttpsServer server(k_loopback_address, k_ephemeral_port, tls_cfg);
    server.get("/ping", [](const httplib::Request&, httplib::Response& res) { res.status = k_http_status_ok; });
    ASSERT_TRUE(server.start_async());
    uint16_t port = server.bound_port();
    ASSERT_GT(port, 0);

    auto ca_file = (find_pki_dir() / "ca" / "ca.crt").string();
    SslCtxPtr client_ctx(SSL_CTX_new(TLS_client_method()));
    ASSERT_NE(client_ctx, nullptr);
    SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_3_VERSION);
    ASSERT_EQ(SSL_CTX_load_verify_locations(client_ctx.get(), ca_file.c_str(), nullptr), 1);

    auto result = execute_tls_client_handshake(port, client_ctx.get());
    EXPECT_TRUE(result.connected);
    EXPECT_EQ(result.negotiated_version, "TLSv1.3");

    server.stop();
}

TEST(DowngradeGuardTest, InsecureProtocolDowngradeToTls12IsRejected) {
    auto tls_cfg = make_valid_tls_config();
    HttpsServer server(k_loopback_address, k_ephemeral_port, tls_cfg);
    server.get("/ping", [](const httplib::Request&, httplib::Response& res) { res.status = k_http_status_ok; });
    ASSERT_TRUE(server.start_async());
    uint16_t port = server.bound_port();
    ASSERT_GT(port, 0);

    auto ca_file = (find_pki_dir() / "ca" / "ca.crt").string();
    SslCtxPtr client_ctx(SSL_CTX_new(TLS_client_method()));
    ASSERT_NE(client_ctx, nullptr);
    SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_2_VERSION);
    ASSERT_EQ(SSL_CTX_load_verify_locations(client_ctx.get(), ca_file.c_str(), nullptr), 1);

    auto result = execute_tls_client_handshake(port, client_ctx.get());
    EXPECT_FALSE(result.connected) << "TLS 1.2 handshake must be strictly rejected by TLS 1.3-only server";
    EXPECT_EQ(result.ssl_error, SSL_ERROR_SSL);

    server.stop();
}

TEST(DowngradeGuardTest, ObsoleteLegacyCiphersAreRejected) {
    auto tls_cfg = make_valid_tls_config();
    HttpsServer server(k_loopback_address, k_ephemeral_port, tls_cfg);
    server.get("/ping", [](const httplib::Request&, httplib::Response& res) { res.status = k_http_status_ok; });
    ASSERT_TRUE(server.start_async());
    uint16_t port = server.bound_port();
    ASSERT_GT(port, 0);

    auto ca_file = (find_pki_dir() / "ca" / "ca.crt").string();
    SslCtxPtr client_ctx(SSL_CTX_new(TLS_client_method()));
    ASSERT_NE(client_ctx, nullptr);
    SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_2_VERSION);
    ASSERT_EQ(SSL_CTX_set_cipher_list(client_ctx.get(), "RC4-SHA:DES-CBC3-SHA:AES128-SHA"), 1);
    ASSERT_EQ(SSL_CTX_load_verify_locations(client_ctx.get(), ca_file.c_str(), nullptr), 1);

    auto result = execute_tls_client_handshake(port, client_ctx.get());
    EXPECT_FALSE(result.connected) << "Legacy ciphers handshake must fail";

    server.stop();
}

} // namespace securecloud::gateway::http
