#include "securecloud/health/transport_probe.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace securecloud::common::health {
namespace {

constexpr uint16_t k_http_port = 80;
constexpr uint16_t k_https_port = 443;
constexpr int k_listen_backlog = 5;
constexpr std::chrono::milliseconds k_test_timeout{250};
constexpr std::chrono::milliseconds k_short_timeout{50};

TEST(TransportProbeTest, InvalidArgumentsFailImmediately) {
    EXPECT_FALSE(probe_tcp_connectivity("", k_http_port));
    EXPECT_FALSE(probe_tcp_connectivity("127.0.0.1", 0));
}

TEST(TransportProbeTest, ConnectToActiveListeningSocketSucceeds) {
    int listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(listen_fd, 0);

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; // Ephemeral port

    ASSERT_EQ(::bind(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)), 0);
    ASSERT_EQ(::listen(listen_fd, k_listen_backlog), 0);

    socklen_t len = sizeof(addr);
    ASSERT_EQ(::getsockname(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), &len), 0);
    uint16_t port = ntohs(addr.sin_port);

    auto start = std::chrono::steady_clock::now();
    bool connected = probe_tcp_connectivity("127.0.0.1", port, k_test_timeout);
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

    ::close(listen_fd);

    EXPECT_TRUE(connected);
    EXPECT_LE(duration.count(), k_test_timeout.count());
}

TEST(TransportProbeTest, ConnectToClosedPortFailsWithinDeadline) {
    int listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(listen_fd, 0);

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    ASSERT_EQ(::bind(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)), 0);

    socklen_t len = sizeof(addr);
    ASSERT_EQ(::getsockname(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), &len), 0);
    uint16_t closed_port = ntohs(addr.sin_port);

    // Close socket so port is closed
    ::close(listen_fd);

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

} // namespace
} // namespace securecloud::common::health
