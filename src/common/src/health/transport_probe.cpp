#include "securecloud/health/transport_probe.hpp"

#include <chrono>
#include <string>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace securecloud::common::health {

namespace {

#ifdef _WIN32
using socket_handle_t = SOCKET;
constexpr socket_handle_t k_invalid_socket = INVALID_SOCKET;

inline void close_socket(socket_handle_t fd) noexcept {
    if (fd != INVALID_SOCKET) {
        ::closesocket(fd);
    }
}

inline void ensure_winsock_initialized() noexcept {
    struct WinsockInit {
        WinsockInit() noexcept {
            WSADATA wsa_data{};
            (void)::WSAStartup(MAKEWORD(2, 2), &wsa_data);
        }
        ~WinsockInit() noexcept { ::WSACleanup(); }
    };
    static WinsockInit init;
}
#else
using socket_handle_t = int;

inline void close_socket(socket_handle_t fd) noexcept {
    if (fd >= 0) {
        ::close(fd);
    }
}

inline void ensure_winsock_initialized() noexcept {}
#endif

class SocketCloser {
  public:
    explicit SocketCloser(socket_handle_t fd) noexcept : fd_(fd) {}
    ~SocketCloser() noexcept { close_socket(fd_); }
    SocketCloser(const SocketCloser&) = delete;
    SocketCloser& operator=(const SocketCloser&) = delete;
    SocketCloser(SocketCloser&&) = delete;
    SocketCloser& operator=(SocketCloser&&) = delete;

  private:
    socket_handle_t fd_;
};

bool check_poll_result(socket_handle_t sockfd, int timeout_ms) noexcept {
#ifdef _WIN32
    WSAPOLLFD pfd{};
    pfd.fd = sockfd;
    pfd.events = POLLOUT;

    int poll_rc = ::WSAPoll(&pfd, 1, timeout_ms > 0 ? timeout_ms : 1);
    if (poll_rc <= 0) {
        return false;
    }

    auto revents = static_cast<unsigned short>(pfd.revents);
    auto pollout = static_cast<unsigned short>(POLLOUT);
    auto pollerr = static_cast<unsigned short>(POLLERR | POLLHUP | POLLNVAL);

    if ((revents & pollout) == 0 || (revents & pollerr) != 0) {
        return false;
    }

    int so_error = 0;
    int len = sizeof(so_error);
    return (::getsockopt(sockfd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_error), &len) == 0 && so_error == 0);
#else
    pollfd pfd{};
    pfd.fd = sockfd;
    pfd.events = POLLOUT;

    int poll_rc = ::poll(&pfd, 1, timeout_ms > 0 ? timeout_ms : 1);
    if (poll_rc <= 0) {
        return false;
    }

    auto revents = static_cast<unsigned short>(pfd.revents);
    auto pollout = static_cast<unsigned short>(POLLOUT);
    auto pollerr = static_cast<unsigned short>(POLLERR | POLLHUP | POLLNVAL);

    if ((revents & pollout) == 0 || (revents & pollerr) != 0) {
        return false;
    }

    int so_error = 0;
    auto len = static_cast<socklen_t>(sizeof(so_error));
    return (::getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len) == 0 && so_error == 0);
#endif
}

bool try_connect_socket(const struct addrinfo& addr, int timeout_ms) noexcept {
    if (timeout_ms <= 0) {
        return false;
    }

    socket_handle_t sockfd = ::socket(addr.ai_family, addr.ai_socktype, addr.ai_protocol);
#ifdef _WIN32
    if (sockfd == INVALID_SOCKET) {
        return false;
    }
#else
    if (sockfd < 0) {
        return false;
    }
#endif

    SocketCloser closer(sockfd);

#ifdef _WIN32
    u_long nonblock_mode = 1;
    if (::ioctlsocket(sockfd, FIONBIO, &nonblock_mode) != 0) {
        return false;
    }
#else
    int flags = ::fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }

    auto uflags = static_cast<unsigned int>(flags);
    auto nonblock = static_cast<unsigned int>(O_NONBLOCK);
    if (::fcntl(sockfd, F_SETFL, static_cast<int>(uflags | nonblock)) < 0) {
        return false;
    }
#endif

#ifdef _WIN32
    int conn_rc = ::connect(sockfd, addr.ai_addr, static_cast<int>(addr.ai_addrlen));
#else
    int conn_rc = ::connect(sockfd, addr.ai_addr, addr.ai_addrlen);
#endif
    if (conn_rc == 0) {
        return true;
    }

#ifdef _WIN32
    if (::WSAGetLastError() == WSAEWOULDBLOCK) {
        return check_poll_result(sockfd, timeout_ms);
    }
#else
    if (errno == EINPROGRESS) {
        return check_poll_result(sockfd, timeout_ms);
    }
#endif

    return false;
}

} // namespace

bool probe_tcp_connectivity(std::string_view host, uint16_t port, std::chrono::milliseconds timeout) noexcept {
    if (host.empty() || port == 0 || timeout <= std::chrono::milliseconds::zero()) {
        return false;
    }

    ensure_winsock_initialized();

    const auto start_time = std::chrono::steady_clock::now();
    const auto deadline = start_time + timeout;

    try {
        std::string host_str(host);
        std::string port_str = std::to_string(port);

        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        struct addrinfo* res = nullptr;
        int rc = ::getaddrinfo(host_str.c_str(), port_str.c_str(), &hints, &res);
        if (rc != 0 || res == nullptr) {
            return false;
        }

        bool connected = false;

        for (struct addrinfo* rp = res; rp != nullptr; rp = rp->ai_next) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                break;
            }
            const auto remaining_ms =
                static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
            if (remaining_ms <= 0) {
                break;
            }

            if (try_connect_socket(*rp, remaining_ms)) {
                connected = true;
                break;
            }
        }

        ::freeaddrinfo(res);
        return connected;
    } catch (...) {
        return false;
    }
}

} // namespace securecloud::common::health
