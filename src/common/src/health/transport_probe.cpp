#include "securecloud/health/transport_probe.hpp"

#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace securecloud::common::health {

namespace {

class SocketCloser {
  public:
    explicit SocketCloser(int fd) noexcept : fd_(fd) {}
    ~SocketCloser() noexcept {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }
    SocketCloser(const SocketCloser&) = delete;
    SocketCloser& operator=(const SocketCloser&) = delete;
    SocketCloser(SocketCloser&&) = delete;
    SocketCloser& operator=(SocketCloser&&) = delete;

  private:
    int fd_;
};

bool check_poll_result(int sockfd, int timeout_ms) noexcept {
    struct pollfd pfd{};
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
}

bool try_connect_socket(const struct addrinfo& addr, int timeout_ms) noexcept {
    int sockfd = ::socket(addr.ai_family, addr.ai_socktype, addr.ai_protocol);
    if (sockfd < 0) {
        return false;
    }

    SocketCloser closer(sockfd);

    int flags = ::fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }

    auto uflags = static_cast<unsigned int>(flags);
    auto nonblock = static_cast<unsigned int>(O_NONBLOCK);
    if (::fcntl(sockfd, F_SETFL, static_cast<int>(uflags | nonblock)) < 0) {
        return false;
    }

    int conn_rc = ::connect(sockfd, addr.ai_addr, addr.ai_addrlen);
    if (conn_rc == 0) {
        return true;
    }

    if (errno == EINPROGRESS) {
        return check_poll_result(sockfd, timeout_ms);
    }

    return false;
}

} // namespace

bool probe_tcp_connectivity(std::string_view host, uint16_t port, std::chrono::milliseconds timeout) noexcept {
    if (host.empty() || port == 0) {
        return false;
    }

    try {
        std::string host_str(host);
        std::string port_str = std::to_string(port);

        struct addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        struct addrinfo* res = nullptr;
        int rc = ::getaddrinfo(host_str.c_str(), port_str.c_str(), &hints, &res);
        if (rc != 0 || res == nullptr) {
            return false;
        }

        bool connected = false;
        const auto timeout_ms = static_cast<int>(timeout.count());

        for (struct addrinfo* rp = res; rp != nullptr; rp = rp->ai_next) {
            if (try_connect_socket(*rp, timeout_ms)) {
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
