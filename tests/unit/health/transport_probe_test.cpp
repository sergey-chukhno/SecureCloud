#include "securecloud/health/transport_probe.hpp"

#include <chrono>
#include <cstdint>
#include <gtest/gtest.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace securecloud::common::health {
namespace {

#ifdef _WIN32
using test_socket_t = SOCKET;
constexpr test_socket_t k_invalid_test_socket = INVALID_SOCKET;

inline void test_close_socket(test_socket_t s) noexcept {
    if (s != INVALID_SOCKET) {
        ::closesocket(s);
    }
}

inline void ensure_test_winsock() noexcept {
    struct WinsockInit {
        WinsockInit() noexcept {
            WSADATA wsa{};
            (void)::WSAStartup(MAKEWORD(2, 2), &wsa);
        }
        ~WinsockInit() noexcept { ::WSACleanup(); }
    };
    static WinsockInit init;
}

using test_socklen_t = int;
#else
using test_socket_t = int;
constexpr test_socket_t k_invalid_test_socket = -1;

inline void test_close_socket(test_socket_t s) noexcept {
    if (s >= 0) {
        ::close(s);
    }
}

inline void ensure_test_winsock() noexcept {}

using test_socklen_t = socklen_t;
#endif

constexpr uint16_t k_http_port = 80;
constexpr uint16_t k_https_port = 443;
constexpr int k_listen_backlog = 5;
constexpr std::chrono::milliseconds k_test_timeout{250};
constexpr std::chrono::milliseconds k_short_timeout{50};
constexpr std::chrono::milliseconds k_scheduler_tolerance{50};
constexpr std::chrono::milliseconds k_zero_timeout{0};
constexpr std::chrono::milliseconds k_negative_timeout{-10};

class ScopedEphemeralListener {
  public:
    ScopedEphemeralListener() {
        ensure_test_winsock();
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ == k_invalid_test_socket) {
            return;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0; // Ephemeral port

        if (::bind(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
            close();
            return;
        }

        if (::listen(fd_, k_listen_backlog) != 0) {
            close();
            return;
        }

        test_socklen_t len = sizeof(addr);
        if (::getsockname(fd_, reinterpret_cast<struct sockaddr*>(&addr), &len) == 0) {
            port_ = ntohs(addr.sin_port);
        }
    }

    ~ScopedEphemeralListener() noexcept { close(); }

    ScopedEphemeralListener(const ScopedEphemeralListener&) = delete;
    ScopedEphemeralListener& operator=(const ScopedEphemeralListener&) = delete;
    ScopedEphemeralListener(ScopedEphemeralListener&&) = delete;
    ScopedEphemeralListener& operator=(ScopedEphemeralListener&&) = delete;

    void close() noexcept {
        if (fd_ != k_invalid_test_socket) {
            test_close_socket(fd_);
            fd_ = k_invalid_test_socket;
        }
    }

    [[nodiscard]] bool is_valid() const noexcept { return fd_ != k_invalid_test_socket && port_ > 0; }
    [[nodiscard]] uint16_t port() const noexcept { return port_; }

  private:
    test_socket_t fd_{k_invalid_test_socket};
    uint16_t port_{0};
};

TEST(TransportProbeTest, InvalidArgumentsFailImmediately) {
    EXPECT_FALSE(probe_tcp_connectivity("", k_http_port));
    EXPECT_FALSE(probe_tcp_connectivity("127.0.0.1", 0));
    EXPECT_FALSE(probe_tcp_connectivity("127.0.0.1", k_http_port, k_zero_timeout));
    EXPECT_FALSE(probe_tcp_connectivity("127.0.0.1", k_http_port, k_negative_timeout));
}

TEST(TransportProbeTest, ConnectToActiveListeningSocketSucceeds) {
    ScopedEphemeralListener listener;
    ASSERT_TRUE(listener.is_valid());

    auto start = std::chrono::steady_clock::now();
    bool connected = probe_tcp_connectivity("127.0.0.1", listener.port(), k_test_timeout);
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

    listener.close();

    EXPECT_TRUE(connected);
    EXPECT_LE(duration.count(), k_test_timeout.count());
}

TEST(TransportProbeTest, ConnectToClosedPortFailsWithinDeadline) {
    ScopedEphemeralListener listener;
    ASSERT_TRUE(listener.is_valid());
    uint16_t closed_port = listener.port();

    // Close socket so port is closed
    listener.close();

    auto start = std::chrono::steady_clock::now();
    bool connected = probe_tcp_connectivity("127.0.0.1", closed_port, k_test_timeout);
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

    EXPECT_FALSE(connected);
    EXPECT_LE(duration.count(), k_test_timeout.count());
}

TEST(TransportProbeTest, TimeoutOnNonRoutableEndpointIsBounded) {
    // 192.0.2.1 is TEST-NET-1 (RFC 5737), reserved for documentation and non-routable.
    auto start = std::chrono::steady_clock::now();
    bool connected = probe_tcp_connectivity("192.0.2.1", k_https_port, k_short_timeout);
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

    EXPECT_FALSE(connected);
    EXPECT_LE(duration.count(), k_test_timeout.count());
}

TEST(TransportProbeTest, MultipleAddressesShareSingleOverallDeadline) {
    ScopedEphemeralListener listener;
    ASSERT_TRUE(listener.is_valid());
    uint16_t closed_port = listener.port();

    // Close socket immediately so port is closed
    listener.close();

    // "localhost" resolves to multiple addresses (IPv6 ::1 and IPv4 127.0.0.1).
    // The complete probe must consume a single shared deadline, not N * timeout.
    auto start = std::chrono::steady_clock::now();
    bool connected = probe_tcp_connectivity("localhost", closed_port, k_test_timeout);
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

    EXPECT_FALSE(connected);
    EXPECT_LE(duration.count(), (k_test_timeout + k_scheduler_tolerance).count());
}

} // namespace
} // namespace securecloud::common::health
