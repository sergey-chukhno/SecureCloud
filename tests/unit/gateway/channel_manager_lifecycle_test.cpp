#include "gateway_config.hpp"
#include "grpc/channel_manager.hpp"

#include <chrono>
#include <filesystem>
#include <future>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace securecloud::gateway::grpc {
namespace {

constexpr auto k_quick_timeout = std::chrono::milliseconds(100);
constexpr const char* k_auth_test_endpoint = "127.0.0.1:50052";
constexpr const char* k_messaging_test_endpoint = "127.0.0.1:50053";
constexpr const char* k_files_test_endpoint = "127.0.0.1:50054";
constexpr const char* k_audit_test_endpoint = "127.0.0.1:50055";
constexpr const char* k_non_listening_endpoint = "127.0.0.1:59999";

std::filesystem::path find_pki_root() {
#ifdef SECURECLOUD_DEV_PKI_DIR
    std::filesystem::path defined_path(SECURECLOUD_DEV_PKI_DIR);
    if (std::filesystem::exists(defined_path / "ca" / "ca.crt")) {
        return defined_path;
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

common::security::SecurityCredentialsConfig get_gateway_credentials_config() {
    auto pki_root = find_pki_root();
    common::security::SecurityCredentialsConfig creds;
    creds.ca_cert_path = pki_root / "ca" / "ca.crt";
    creds.service_cert_path = pki_root / "services" / "gateway" / "gateway.crt";
    creds.service_key_path = pki_root / "services" / "gateway" / "gateway.key";
    return creds;
}

TEST(ChannelManagerLifecycleTest, InitialStateQueriesForUnknownService) {
    auto creds = get_gateway_credentials_config();
    GrpcChannelManager manager(creds, k_auth_test_endpoint, k_messaging_test_endpoint, k_files_test_endpoint,
                               k_audit_test_endpoint);

    EXPECT_EQ(manager.get_connection_state("non_existent_service", false), GRPC_CHANNEL_SHUTDOWN);
    EXPECT_EQ(manager.get_connection_state("non_existent_service", true), GRPC_CHANNEL_SHUTDOWN);
    EXPECT_FALSE(manager.is_channel_ready("non_existent_service"));
    EXPECT_FALSE(manager.is_channel_healthy("non_existent_service"));
}

TEST(ChannelManagerLifecycleTest, UncachedServiceStateTransitions) {
    auto creds = get_gateway_credentials_config();
    GrpcChannelManager manager(creds, k_auth_test_endpoint, k_messaging_test_endpoint, k_files_test_endpoint,
                               k_audit_test_endpoint);

    // Uncached without try_to_connect returns SHUTDOWN
    EXPECT_EQ(manager.get_connection_state(GrpcChannelManager::k_service_auth, false), GRPC_CHANNEL_SHUTDOWN);

    // Uncached with try_to_connect initializes channel into IDLE or CONNECTING
    auto state = manager.get_connection_state(GrpcChannelManager::k_service_auth, true);
    EXPECT_TRUE(state == GRPC_CHANNEL_IDLE || state == GRPC_CHANNEL_CONNECTING);
    EXPECT_TRUE(manager.is_channel_healthy(GrpcChannelManager::k_service_auth));
    EXPECT_FALSE(manager.is_channel_ready(GrpcChannelManager::k_service_auth));
}

TEST(ChannelManagerLifecycleTest, WaitForConnectedFailsGracefullyOnNonListeningEndpoint) {
    auto creds = get_gateway_credentials_config();
    GrpcChannelManager manager(creds, k_non_listening_endpoint, k_messaging_test_endpoint, k_files_test_endpoint,
                               k_audit_test_endpoint);

    bool connected = manager.wait_for_connected(GrpcChannelManager::k_service_auth, k_quick_timeout);
    EXPECT_FALSE(connected);
}

TEST(ChannelManagerLifecycleTest, ReconnectEvictsAndRecreatesChannel) {
    auto creds = get_gateway_credentials_config();
    GrpcChannelManager manager(creds, k_auth_test_endpoint, k_messaging_test_endpoint, k_files_test_endpoint,
                               k_audit_test_endpoint);

    auto chan1 = manager.get_auth_channel();
    ASSERT_NE(chan1, nullptr);
    EXPECT_EQ(manager.cached_channel_count(), 1);

    bool reconnected = manager.reconnect(GrpcChannelManager::k_service_auth);
    EXPECT_TRUE(reconnected);
    EXPECT_EQ(manager.cached_channel_count(), 1);

    auto chan2 = manager.get_auth_channel();
    ASSERT_NE(chan2, nullptr);
    EXPECT_NE(chan1, chan2);

    // Reconnecting unknown service returns false
    EXPECT_FALSE(manager.reconnect("invalid_service"));
}

TEST(ChannelManagerLifecycleTest, ResetFlushesAllCachedChannels) {
    auto creds = get_gateway_credentials_config();
    GrpcChannelManager manager(creds, k_auth_test_endpoint, k_messaging_test_endpoint, k_files_test_endpoint,
                               k_audit_test_endpoint);

    EXPECT_NE(manager.get_auth_channel(), nullptr);
    EXPECT_NE(manager.get_messaging_channel(), nullptr);
    EXPECT_NE(manager.get_files_channel(), nullptr);
    EXPECT_NE(manager.get_audit_channel(), nullptr);
    EXPECT_EQ(manager.cached_channel_count(), 4);

    manager.reset();
    EXPECT_EQ(manager.cached_channel_count(), 0);
    EXPECT_EQ(manager.get_connection_state(GrpcChannelManager::k_service_auth, false), GRPC_CHANNEL_SHUTDOWN);
}

TEST(ChannelManagerLifecycleTest, ConcurrentAccessThreadSafety) {
    auto creds = get_gateway_credentials_config();
    GrpcChannelManager manager(creds, k_auth_test_endpoint, k_messaging_test_endpoint, k_files_test_endpoint,
                               k_audit_test_endpoint);

    constexpr int k_num_threads = 8;
    constexpr int k_iterations = 50;

    std::vector<std::future<void>> futures;
    futures.reserve(k_num_threads);

    for (int t = 0; t < k_num_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&manager, t]() {
            for (int i = 0; i < k_iterations; ++i) {
                if (t % 4 == 0) {
                    (void)manager.get_auth_channel();
                } else if (t % 4 == 1) {
                    (void)manager.get_connection_state(GrpcChannelManager::k_service_auth, false);
                } else if (t % 4 == 2) {
                    (void)manager.is_channel_healthy(GrpcChannelManager::k_service_auth);
                } else {
                    if (i % 10 == 0) {
                        (void)manager.reconnect(GrpcChannelManager::k_service_auth);
                    }
                }
            }
        }));
    }

    for (auto& f : futures) {
        f.get();
    }

    EXPECT_TRUE(manager.cached_channel_count() <= 1);
}

} // namespace
} // namespace securecloud::gateway::grpc

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
#ifdef _WIN32
    std::fflush(nullptr);
    ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(result));
#else
    return result;
#endif
}
