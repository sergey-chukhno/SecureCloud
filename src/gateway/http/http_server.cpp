#include "http/http_server.hpp"

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

#include <atomic>
#include <chrono>
#include <httplib.h>
#include <memory>
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

struct HttpServer::Impl {
    std::string listen_address;
    uint16_t listen_port{0};
    uint16_t bound_port{0};
    uint32_t threads{k_default_server_threads};
    uint64_t max_payload_bytes{k_default_max_payload_bytes};
    std::chrono::milliseconds timeout{k_default_timeout};
    std::atomic<ServerState> state{ServerState::Stopped};

    std::unique_ptr<httplib::Server> server;
    std::thread worker_thread;

    Impl(std::string host, uint16_t port, uint32_t num_threads, uint64_t max_payload,
         std::chrono::milliseconds req_timeout)
        : listen_address(std::move(host)), listen_port(port), threads(num_threads), max_payload_bytes(max_payload),
          timeout(req_timeout), server(std::make_unique<httplib::Server>()) {
        ensure_winsock_initialized();

        server->new_task_queue = [thread_count = threads] { return new httplib::ThreadPool(thread_count); };
        server->set_payload_max_length(max_payload_bytes);
        server->set_read_timeout(timeout);
        server->set_write_timeout(timeout);
    }

    ~Impl() {
        // Safe destruction: join worker thread if still running
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

HttpServer::HttpServer(const GatewayConfig& config)
    : HttpServer(config.http_listen_address, config.http_listen_port, config.server_threads, config.max_payload_bytes,
                 config.request_timeout_ms) {}

HttpServer::HttpServer(std::string host, uint16_t port, uint32_t threads, uint64_t max_payload_bytes,
                       std::chrono::milliseconds timeout)
    : impl_(std::make_unique<Impl>(std::move(host), port, threads, max_payload_bytes, timeout)) {}

HttpServer::~HttpServer() {
    stop();
}

HttpServer::HttpServer(HttpServer&&) noexcept = default;
HttpServer& HttpServer::operator=(HttpServer&&) noexcept = default;

bool HttpServer::start_async() {
    if (!impl_) {
        return false;
    }

    ServerState expected = ServerState::Stopped;
    if (!impl_->state.compare_exchange_strong(expected, ServerState::Running)) {
        return false;
    }

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

void HttpServer::stop() noexcept {
    if (!impl_) {
        return;
    }

    ServerState expected = ServerState::Running;
    if (!impl_->state.compare_exchange_strong(expected, ServerState::Draining)) {
        return;
    }

    if (impl_->server) {
        impl_->server->stop();
    }

    if (impl_->worker_thread.joinable()) {
        impl_->worker_thread.join();
    }

    impl_->state.store(ServerState::Stopped);
}

void HttpServer::wait_until_ready() const {
    if (impl_ && impl_->server) {
        impl_->server->wait_until_ready();
    }
}

ServerState HttpServer::state() const noexcept {
    if (!impl_) {
        return ServerState::Stopped;
    }
    return impl_->state.load();
}

bool HttpServer::is_running() const noexcept {
    return state() == ServerState::Running;
}

uint16_t HttpServer::bound_port() const noexcept {
    if (!impl_) {
        return 0;
    }
    return impl_->bound_port;
}

const std::string& HttpServer::listen_address() const noexcept {
    static const std::string k_empty;
    if (!impl_) {
        return k_empty;
    }
    return impl_->listen_address;
}

void HttpServer::get(const std::string& pattern, HttpHandler handler) {
    if (impl_ && impl_->server) {
        impl_->server->Get(pattern, std::move(handler));
    }
}

void HttpServer::post(const std::string& pattern, HttpHandler handler) {
    if (impl_ && impl_->server) {
        impl_->server->Post(pattern, std::move(handler));
    }
}

void HttpServer::put(const std::string& pattern, HttpHandler handler) {
    if (impl_ && impl_->server) {
        impl_->server->Put(pattern, std::move(handler));
    }
}

void HttpServer::del(const std::string& pattern, HttpHandler handler) {
    if (impl_ && impl_->server) {
        impl_->server->Delete(pattern, std::move(handler));
    }
}

httplib::Server& HttpServer::raw_server() noexcept {
    return *impl_->server;
}

} // namespace securecloud::gateway::http
