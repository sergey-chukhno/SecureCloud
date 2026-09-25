#include "http/http_redirect_server.hpp"

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

constexpr uint32_t k_default_redirect_threads = 2;
constexpr auto k_default_timeout = std::chrono::milliseconds(5000);
constexpr int k_http_status_permanent_redirect = 308;
constexpr uint16_t k_standard_https_port = 443;
constexpr const char* k_hsts_header_value = "max-age=31536000; includeSubDomains; preload";

std::string extract_host_without_port(const std::string& host_header) {
    if (host_header.empty()) {
        return "";
    }

    // IPv6 literal check, e.g. [::1]:8080 or [::1]
    if (host_header.front() == '[') {
        auto closing_bracket = host_header.find(']');
        if (closing_bracket != std::string::npos) {
            return host_header.substr(0, closing_bracket + 1);
        }
    }

    // IPv4 or domain name with optional port, e.g. localhost:8080 -> localhost
    auto colon_pos = host_header.find(':');
    if (colon_pos != std::string::npos) {
        return host_header.substr(0, colon_pos);
    }

    return host_header;
}

} // namespace

struct HttpRedirectServer::Impl {
    std::string listen_address;
    uint16_t http_port{0};
    uint16_t https_port{0};
    uint16_t bound_port{0};
    uint32_t threads{k_default_redirect_threads};
    std::chrono::milliseconds timeout{k_default_timeout};
    std::atomic<ServerState> state{ServerState::Stopped};

    std::unique_ptr<httplib::Server> server;
    std::thread worker_thread;

    Impl(std::string host, uint16_t listen_p, uint16_t target_https_p, uint32_t num_threads,
         std::chrono::milliseconds req_timeout)
        : listen_address(std::move(host)), http_port(listen_p), https_port(target_https_p), threads(num_threads),
          timeout(req_timeout), server(std::make_unique<httplib::Server>()) {
        ensure_winsock_initialized();

        server->new_task_queue = [thread_count = threads] { return new httplib::ThreadPool(thread_count); };
        server->set_read_timeout(timeout);
        server->set_write_timeout(timeout);
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

HttpRedirectServer::HttpRedirectServer(const GatewayConfig& config)
    : HttpRedirectServer(config.http_listen_address, config.http_listen_port, config.tls.https_listen_port,
                         k_default_redirect_threads, config.request_timeout_ms) {}

HttpRedirectServer::HttpRedirectServer(std::string host, uint16_t http_port, uint16_t https_port, uint32_t threads,
                                       std::chrono::milliseconds timeout)
    : impl_(std::make_unique<Impl>(std::move(host), http_port, https_port, threads, timeout)) {
    impl_->server->set_pre_routing_handler([this](const httplib::Request& req, httplib::Response& res) {
        std::string host_header = req.get_header_value("Host");
        std::string target = req.target.empty() ? "/" : req.target;
        std::string location = build_redirect_url(host_header, target);

        res.status = k_http_status_permanent_redirect;
        res.set_header("Location", location);
        res.set_header("Strict-Transport-Security", k_hsts_header_value);
        res.set_header("Connection", "close");
        res.set_content("Redirecting to HTTPS...\n", "text/plain");

        return httplib::Server::HandlerResponse::Handled;
    });
}

HttpRedirectServer::~HttpRedirectServer() {
    stop();
}

HttpRedirectServer::HttpRedirectServer(HttpRedirectServer&&) noexcept = default;
HttpRedirectServer& HttpRedirectServer::operator=(HttpRedirectServer&&) noexcept = default;

std::string HttpRedirectServer::build_redirect_url(const std::string& host_header,
                                                   const std::string& target_path) const {
    std::string host = extract_host_without_port(host_header);
    if (host.empty()) {
        host = impl_->listen_address.empty() ? "127.0.0.1" : impl_->listen_address;
    }

    std::string path = target_path;
    if (path.empty() || path.front() != '/') {
        path = "/" + path;
    }

    std::string url = "https://" + host;
    if (impl_->https_port != k_standard_https_port && impl_->https_port != 0) {
        url += ":" + std::to_string(impl_->https_port);
    }
    url += path;

    return url;
}

bool HttpRedirectServer::start_async() {
    if (!impl_) {
        return false;
    }

    ServerState expected = ServerState::Stopped;
    if (!impl_->state.compare_exchange_strong(expected, ServerState::Running)) {
        return false;
    }

    if (impl_->http_port == 0) {
        int assigned = impl_->server->bind_to_any_port(impl_->listen_address);
        if (assigned <= 0) {
            impl_->state.store(ServerState::Stopped);
            return false;
        }
        impl_->bound_port = static_cast<uint16_t>(assigned);
    } else {
        if (!impl_->server->bind_to_port(impl_->listen_address, impl_->http_port)) {
            impl_->state.store(ServerState::Stopped);
            return false;
        }
        impl_->bound_port = impl_->http_port;
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

void HttpRedirectServer::stop() noexcept {
    if (!impl_) {
        return;
    }

    ServerState current = impl_->state.load();
    if (current == ServerState::Stopped) {
        return;
    }

    impl_->state.store(ServerState::Draining);

    if (impl_->server) {
        impl_->server->stop();
    }

    if (impl_->worker_thread.joinable()) {
        impl_->worker_thread.join();
    }

    impl_->state.store(ServerState::Stopped);
}

void HttpRedirectServer::wait_until_ready() const {
    if (impl_ && impl_->server) {
        impl_->server->wait_until_ready();
    }
}

ServerState HttpRedirectServer::state() const noexcept {
    return impl_ ? impl_->state.load() : ServerState::Stopped;
}

bool HttpRedirectServer::is_running() const noexcept {
    return state() == ServerState::Running;
}

uint16_t HttpRedirectServer::bound_port() const noexcept {
    return impl_ ? impl_->bound_port : 0;
}

uint16_t HttpRedirectServer::https_target_port() const noexcept {
    return impl_ ? impl_->https_port : 0;
}

const std::string& HttpRedirectServer::listen_address() const noexcept {
    static const std::string k_empty;
    return impl_ ? impl_->listen_address : k_empty;
}

} // namespace securecloud::gateway::http
