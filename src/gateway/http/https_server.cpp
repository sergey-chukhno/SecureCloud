#include "http/https_server.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "tls/tls_handler.hpp"

#include <atomic>
#include <chrono>
#include <httplib.h>
#include <memory>
#include <openssl/ssl.h>
#include <string>
#include <thread>
#include <utility>

namespace securecloud::gateway::http {

namespace {

#ifdef _WIN32
struct WinsockInitGuard {
    WinsockInitGuard() noexcept {
        WSADATA wsa_data{};
        (void)::WSAStartup(MAKEWORD(2, 2), &wsa_data);
    }
    ~WinsockInitGuard() noexcept { ::WSACleanup(); }
};

void ensure_winsock_initialized() noexcept {
    static const WinsockInitGuard k_winsock_guard;
    (void)k_winsock_guard;
}
#else
void ensure_winsock_initialized() noexcept {}
#endif

constexpr uint32_t k_default_server_threads = 4;
constexpr uint64_t k_default_max_payload_bytes = 10485760;
constexpr auto k_default_timeout = std::chrono::milliseconds(5000);

} // namespace

struct HttpsServer::Impl {
    std::string listen_address;
    uint16_t listen_port{0};
    uint16_t bound_port{0};
    GatewayTlsConfig tls_config;
    uint32_t threads{k_default_server_threads};
    uint64_t max_payload_bytes{k_default_max_payload_bytes};
    std::chrono::milliseconds timeout{k_default_timeout};
    std::atomic<ServerState> state{ServerState::Stopped};

    std::unique_ptr<httplib::SSLServer> server;
    std::thread worker_thread;

    Impl(std::string host, uint16_t port, GatewayTlsConfig tls_cfg, uint32_t num_threads, uint64_t max_payload,
         std::chrono::milliseconds req_timeout)
        : listen_address(std::move(host)), listen_port(port), tls_config(std::move(tls_cfg)), threads(num_threads),
          max_payload_bytes(max_payload), timeout(req_timeout) {
        ensure_winsock_initialized();

        try {
            server = std::make_unique<httplib::SSLServer>(tls_config.cert_path.c_str(), tls_config.key_path.c_str());
        } catch (...) {
            server = nullptr;
        }

        if (server) {
            server->new_task_queue = [thread_count = threads] { return new httplib::ThreadPool(thread_count); };
            server->set_payload_max_length(max_payload_bytes);
            server->set_read_timeout(timeout);
            server->set_write_timeout(timeout);
            server->set_default_headers({
                {"Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload"},
            });
        }
    }

    ~Impl() {
        if (state.load() == ServerState::Running || state.load() == ServerState::Draining) {
            if (server) {
                server->stop();
            }
            if (worker_thread.joinable()) {
                worker_thread.join();
            }
            state.store(ServerState::Stopped);
        }
    }

    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    Impl(Impl&&) = delete;
    Impl& operator=(Impl&&) = delete;
};

HttpsServer::HttpsServer(const GatewayConfig& config)
    : HttpsServer(config.http_listen_address, config.tls.https_listen_port, config.tls, config.server_threads,
                  config.limits.max_body_bytes, std::chrono::milliseconds(config.limits.read_timeout_ms)) {}

HttpsServer::HttpsServer(std::string host, uint16_t port, GatewayTlsConfig tls_config, uint32_t threads,
                         uint64_t max_payload_bytes, std::chrono::milliseconds timeout)
    : impl_(std::make_unique<Impl>(std::move(host), port, std::move(tls_config), threads, max_payload_bytes, timeout)) {
}

HttpsServer::~HttpsServer() {
    stop();
}

HttpsServer::HttpsServer(HttpsServer&&) noexcept = default;
HttpsServer& HttpsServer::operator=(HttpsServer&&) noexcept = default;

bool HttpsServer::start_async() {
    if (!impl_ || !impl_->server) {
        return false;
    }

    ServerState expected = ServerState::Stopped;
    if (!impl_->state.compare_exchange_strong(expected, ServerState::Running)) {
        return false;
    }

    // 1. Fail-closed certificate & key validation
    std::string cert_err;
    if (!tls::TlsHandler::validate_certificate_pair(impl_->tls_config.cert_path, impl_->tls_config.key_path,
                                                    cert_err)) {
        impl_->state.store(ServerState::Stopped);
        return false;
    }

    // 2. Validate SSLServer internal context validity
    if (!impl_->server->is_valid()) {
        impl_->state.store(ServerState::Stopped);
        return false;
    }

    // 3. Configure TLS 1.3 protocol clamping, AEAD ciphersuites, and ALPN
    auto* ssl_ctx = static_cast<SSL_CTX*>(impl_->server->tls_context());
    if (ssl_ctx == nullptr) {
        impl_->state.store(ServerState::Stopped);
        return false;
    }

    std::string config_err;
    if (!tls::TlsHandler::configure_server_context(ssl_ctx, impl_->tls_config, config_err)) {
        impl_->state.store(ServerState::Stopped);
        return false;
    }

    // 4. Bind listening port
    if (impl_->listen_port == 0) {
        int assigned = impl_->server->bind_to_any_port(impl_->listen_address);
        if (assigned <= 0) {
            impl_->state.store(ServerState::Stopped);
            return false;
        }
        impl_->bound_port = static_cast<uint16_t>(assigned);
    } else {
        if (!impl_->server->bind_to_port(impl_->listen_address, impl_->listen_port)) {
            impl_->state.store(ServerState::Stopped);
            return false;
        }
        impl_->bound_port = impl_->listen_port;
    }

    // 5. Spawn background listening thread
    impl_->worker_thread = std::thread([this] { impl_->server->listen_after_bind(); });

    impl_->server->wait_until_ready();
    if (!impl_->server->is_running()) {
        if (impl_->worker_thread.joinable()) {
            impl_->worker_thread.join();
        }
        impl_->state.store(ServerState::Stopped);
        return false;
    }

    return true;
}

bool HttpsServer::start(const std::string& host, uint16_t port) {
    if (!impl_) {
        return false;
    }
    impl_->listen_address = host;
    impl_->listen_port = port;
    return start_async();
}

void HttpsServer::stop() noexcept {
    if (!impl_) {
        return;
    }

    ServerState expected = ServerState::Running;
    if (impl_->state.compare_exchange_strong(expected, ServerState::Draining)) {
        if (impl_->server) {
            impl_->server->stop();
        }
        if (impl_->worker_thread.joinable()) {
            impl_->worker_thread.join();
        }
        impl_->state.store(ServerState::Stopped);
    }
}

void HttpsServer::wait_until_ready() const {
    if (impl_ && impl_->server) {
        impl_->server->wait_until_ready();
    }
}

ServerState HttpsServer::state() const noexcept {
    return impl_ ? impl_->state.load() : ServerState::Stopped;
}

bool HttpsServer::is_running() const noexcept {
    return impl_ && impl_->server && impl_->server->is_running();
}

uint16_t HttpsServer::bound_port() const noexcept {
    return impl_ ? impl_->bound_port : 0;
}

const std::string& HttpsServer::listen_address() const noexcept {
    static const std::string k_empty;
    return impl_ ? impl_->listen_address : k_empty;
}

const GatewayTlsConfig& HttpsServer::tls_config() const {
    if (impl_) {
        return impl_->tls_config;
    }
    static const GatewayTlsConfig k_default_tls;
    return k_default_tls;
}

void HttpsServer::get(const std::string& pattern, HttpHandler handler) {
    if (impl_ && impl_->server) {
        impl_->server->Get(pattern, std::move(handler));
    }
}

void HttpsServer::post(const std::string& pattern, HttpHandler handler) {
    if (impl_ && impl_->server) {
        impl_->server->Post(pattern, std::move(handler));
    }
}

void HttpsServer::put(const std::string& pattern, HttpHandler handler) {
    if (impl_ && impl_->server) {
        impl_->server->Put(pattern, std::move(handler));
    }
}

void HttpsServer::del(const std::string& pattern, HttpHandler handler) {
    if (impl_ && impl_->server) {
        impl_->server->Delete(pattern, std::move(handler));
    }
}

httplib::SSLServer& HttpsServer::raw_server() noexcept {
    return *impl_->server;
}

} // namespace securecloud::gateway::http
