#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <cstddef>
#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace securecloud::gateway {
namespace {

constexpr int k_expected_uptime_seconds = 3600;
constexpr int k_expected_active_connections = 42;
constexpr int k_http_status_ok = 200;
constexpr int k_https_default_port = 443;
constexpr size_t k_expected_features_count = 4;

TEST(HttpSmokeTest, JsonSerializationAndDeserializationRoundtrip) {
    nlohmann::json payload;
    payload["service"] = "securecloud-gateway";
    payload["status"] = "SERVING";
    payload["version"] = 1;
    payload["features"] = {"auth", "messaging", "files", "audit"};
    payload["metrics"] = {
        {"uptime_s", k_expected_uptime_seconds},
        {"active_connections", k_expected_active_connections},
    };

    const std::string serialized = payload.dump();
    EXPECT_FALSE(serialized.empty());

    const auto parsed = nlohmann::json::parse(serialized);
    EXPECT_EQ(parsed["service"], "securecloud-gateway");
    EXPECT_EQ(parsed["status"], "SERVING");
    EXPECT_EQ(parsed["version"], 1);
    ASSERT_TRUE(parsed["features"].is_array());
    EXPECT_EQ(parsed["features"].size(), k_expected_features_count);
    EXPECT_EQ(parsed["features"][0], "auth");
    EXPECT_EQ(parsed["metrics"]["uptime_s"], k_expected_uptime_seconds);
    EXPECT_EQ(parsed["metrics"]["active_connections"], k_expected_active_connections);
}

TEST(HttpSmokeTest, HttplibRequestAndResponseObjectLifecycle) {
    httplib::Request req;
    req.method = "GET";
    req.path = "/health/ready";
    req.set_header("X-Request-ID", "req-test-uuid-001");
    req.set_header("Accept", "application/json");
    req.body = R"({"check":"readiness"})";

    EXPECT_EQ(req.method, "GET");
    EXPECT_EQ(req.path, "/health/ready");
    EXPECT_TRUE(req.has_header("X-Request-ID"));
    EXPECT_EQ(req.get_header_value("X-Request-ID"), "req-test-uuid-001");
    EXPECT_TRUE(req.has_header("Accept"));
    EXPECT_EQ(req.get_header_value("Accept"), "application/json");
    EXPECT_EQ(req.body, R"({"check":"readiness"})");

    httplib::Response res;
    res.status = k_http_status_ok;
    res.set_content(R"({"status":"SERVING"})", "application/json");
    res.set_header("X-Gateway-Version", "0.1.0");

    EXPECT_EQ(res.status, k_http_status_ok);
    EXPECT_EQ(res.body, R"({"status":"SERVING"})");
    EXPECT_TRUE(res.has_header("Content-Type"));
    EXPECT_EQ(res.get_header_value("Content-Type"), "application/json");
    EXPECT_TRUE(res.has_header("X-Gateway-Version"));
    EXPECT_EQ(res.get_header_value("X-Gateway-Version"), "0.1.0");
}

TEST(HttpSmokeTest, HttplibOpenSslSupportCompileDefinitionActive) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    SUCCEED() << "CPPHTTPLIB_OPENSSL_SUPPORT is active and enabled";
    httplib::SSLClient client("localhost", k_https_default_port);
    (void)client;
#else
    FAIL() << "CPPHTTPLIB_OPENSSL_SUPPORT must be defined and active on securecloud::httplib";
#endif
}

} // namespace
} // namespace securecloud::gateway
