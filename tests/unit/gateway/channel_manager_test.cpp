#include "gateway_config.hpp"
#include "grpc/channel_manager.hpp"

#include <chrono>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>

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
constexpr size_t k_expected_four_services = 4;
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

TEST(ChannelManagerTest, ChannelCreationWithPkiCredentials) {
    auto creds = get_gateway_credentials_config();
    GrpcChannelManager manager(creds, k_auth_test_endpoint, k_messaging_test_endpoint, k_files_test_endpoint,
                               k_audit_test_endpoint);

    auto auth_chan = manager.get_auth_channel();
    ASSERT_NE(auth_chan, nullptr);

    auto msg_chan = manager.get_messaging_channel();
    ASSERT_NE(msg_chan, nullptr);

    auto files_chan = manager.get_files_channel();
    ASSERT_NE(files_chan, nullptr);

    auto audit_chan = manager.get_audit_channel();
    ASSERT_NE(audit_chan, nullptr);

    EXPECT_EQ(manager.cached_channel_count(), k_expected_four_services);
}

TEST(ChannelManagerTest, ChannelCachingReusesSameInstance) {
    auto creds = get_gateway_credentials_config();
    GrpcChannelManager manager(creds, k_auth_test_endpoint, k_messaging_test_endpoint, k_files_test_endpoint,
                               k_audit_test_endpoint);

    auto chan1 = manager.get_channel(GrpcChannelManager::k_service_auth);
    auto chan2 = manager.get_channel(GrpcChannelManager::k_service_auth);

    ASSERT_NE(chan1, nullptr);
    ASSERT_NE(chan2, nullptr);
    EXPECT_EQ(chan1, chan2);
    EXPECT_EQ(manager.cached_channel_count(), 1);
}

TEST(ChannelManagerTest, ConnectivityCheckFailsClosedOnUnreachableEndpoint) {
    auto creds = get_gateway_credentials_config();
    GrpcChannelManager manager(creds, k_non_listening_endpoint, k_messaging_test_endpoint, k_files_test_endpoint,
                               k_audit_test_endpoint);

    // Non-throwing guarantee: must cleanly return false within timeout without throwing
    bool connected = manager.check_connectivity(GrpcChannelManager::k_service_auth, k_quick_timeout);
    EXPECT_FALSE(connected);
}

TEST(ChannelManagerTest, RejectsUnknownServiceName) {
    auto creds = get_gateway_credentials_config();
    GrpcChannelManager manager(creds, k_auth_test_endpoint, k_messaging_test_endpoint, k_files_test_endpoint,
                               k_audit_test_endpoint);

    auto chan = manager.get_channel("unknown_service");
    EXPECT_EQ(chan, nullptr);

    bool connected = manager.check_connectivity("unknown_service", k_quick_timeout);
    EXPECT_FALSE(connected);
}

TEST(ChannelManagerTest, ResetClearsCachedChannels) {
    auto creds = get_gateway_credentials_config();
    GrpcChannelManager manager(creds, k_auth_test_endpoint, k_messaging_test_endpoint, k_files_test_endpoint,
                               k_audit_test_endpoint);

    auto chan1 = manager.get_channel(GrpcChannelManager::k_service_messaging);
    ASSERT_NE(chan1, nullptr);
    EXPECT_EQ(manager.cached_channel_count(), 1);

    manager.reset();
    EXPECT_EQ(manager.cached_channel_count(), 0);

    auto chan2 = manager.get_channel(GrpcChannelManager::k_service_messaging);
    ASSERT_NE(chan2, nullptr);
    EXPECT_EQ(manager.cached_channel_count(), 1);
}

TEST(ChannelManagerTest, InitializesFromGatewayConfig) {
    auto creds = get_gateway_credentials_config();
    GatewayConfig config;
    config.common.tls_credentials = creds;
    config.auth_endpoint = k_auth_test_endpoint;
    config.messaging_endpoint = k_messaging_test_endpoint;
    config.files_endpoint = k_files_test_endpoint;
    config.audit_endpoint = k_audit_test_endpoint;

    GrpcChannelManager manager(config);
    auto auth_chan = manager.get_auth_channel();
    ASSERT_NE(auth_chan, nullptr);
    EXPECT_EQ(manager.cached_channel_count(), 1);
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
