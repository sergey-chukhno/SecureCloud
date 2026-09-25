#include "gateway_config.hpp"
#include "http/middleware.hpp"
#include "http/request_id_middleware.hpp"
#include "http/resource_limiter_middleware.hpp"
#include "http/router.hpp"

#include <chrono>
#include <cstdint>
#include <future>
#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <string>

namespace securecloud::gateway::http {
namespace {

constexpr size_t k_test_max_header_bytes = 1024;
constexpr size_t k_test_max_body_bytes = 4096;
constexpr size_t k_test_max_concurrent = 2;
constexpr int k_http_status_ok = 200;
constexpr int k_http_status_payload_too_large = 413;
constexpr int k_http_status_header_too_large = 431;
constexpr int k_http_status_service_unavailable = 503;
constexpr size_t k_oversized_header_len = 1500;
constexpr size_t k_oversized_body_len = 5000;
constexpr size_t k_large_content_length_val = 50000;

GatewayResourceLimitsConfig create_test_limits() {
    GatewayResourceLimitsConfig limits;
    limits.max_header_bytes = k_test_max_header_bytes;
    limits.max_body_bytes = k_test_max_body_bytes;
    limits.max_concurrent_connections = k_test_max_concurrent;
    return limits;
}

void verify_problem_details(const httplib::Response& res, int expected_status, const std::string& expected_type) {
    EXPECT_EQ(res.status, expected_status);
    EXPECT_EQ(res.get_header_value("Content-Type"), ResourceLimiterMiddleware::k_content_type_problem_json);

    auto parsed = nlohmann::json::parse(res.body);
    EXPECT_EQ(parsed["status"], expected_status);
    EXPECT_EQ(parsed["type"], expected_type);
    EXPECT_FALSE(parsed["title"].get<std::string>().empty());
    EXPECT_FALSE(parsed["detail"].get<std::string>().empty());
}

TEST(ResourceLimiterMiddlewareTest, PassesThroughUnderLimits) {
    auto limits = create_test_limits();
    ResourceLimiterMiddleware middleware(limits);

    httplib::Request req;
    req.headers.emplace("X-Custom", "small-value");
    req.body = "valid-small-body";

    httplib::Response res;
    bool next_invoked = false;

    middleware.process(req, res, [&next_invoked](const httplib::Request&, httplib::Response& r) {
        next_invoked = true;
        r.status = k_http_status_ok;
        r.set_content("success", "text/plain");
    });

    EXPECT_TRUE(next_invoked);
    EXPECT_EQ(res.status, k_http_status_ok);
    EXPECT_EQ(res.body, "success");
    EXPECT_EQ(middleware.active_connections(), 0);
}

TEST(ResourceLimiterMiddlewareTest, RejectsHeaderTooLargeWith431) {
    auto limits = create_test_limits();
    ResourceLimiterMiddleware middleware(limits);

    httplib::Request req;
    std::string huge_val(k_oversized_header_len, 'H');
    req.headers.emplace("X-Huge-Header", huge_val);

    httplib::Response res;
    bool next_invoked = false;

    middleware.process(req, res, [&next_invoked](const httplib::Request&, httplib::Response&) { next_invoked = true; });

    EXPECT_FALSE(next_invoked);
    verify_problem_details(res, k_http_status_header_too_large, "urn:securecloud:error:header_too_large");
    EXPECT_EQ(middleware.active_connections(), 0);
}

TEST(ResourceLimiterMiddlewareTest, RejectsContentLengthTooLargeWith413) {
    auto limits = create_test_limits();
    ResourceLimiterMiddleware middleware(limits);

    httplib::Request req;
    req.headers.emplace("Content-Length", std::to_string(k_large_content_length_val));

    httplib::Response res;
    bool next_invoked = false;

    middleware.process(req, res, [&next_invoked](const httplib::Request&, httplib::Response&) { next_invoked = true; });

    EXPECT_FALSE(next_invoked);
    verify_problem_details(res, k_http_status_payload_too_large, "urn:securecloud:error:payload_too_large");
    EXPECT_EQ(middleware.active_connections(), 0);
}

TEST(ResourceLimiterMiddlewareTest, RejectsActualBodyTooLargeWith413) {
    auto limits = create_test_limits();
    ResourceLimiterMiddleware middleware(limits);

    httplib::Request req;
    req.body = std::string(k_oversized_body_len, 'B');

    httplib::Response res;
    bool next_invoked = false;

    middleware.process(req, res, [&next_invoked](const httplib::Request&, httplib::Response&) { next_invoked = true; });

    EXPECT_FALSE(next_invoked);
    verify_problem_details(res, k_http_status_payload_too_large, "urn:securecloud:error:payload_too_large");
    EXPECT_EQ(middleware.active_connections(), 0);
}

TEST(ResourceLimiterMiddlewareTest, RejectsWhenConcurrentConnectionsExceededWith503) {
    auto limits = create_test_limits();
    ResourceLimiterMiddleware middleware(limits);

    std::promise<void> hold_p1;
    std::promise<void> hold_p2;
    std::promise<void> ready_p1;
    std::promise<void> ready_p2;

    auto f1 = std::async(std::launch::async, [&] {
        httplib::Request r1;
        httplib::Response s1;
        middleware.process(r1, s1, [&](const httplib::Request&, httplib::Response&) {
            ready_p1.set_value();
            hold_p1.get_future().wait();
        });
    });

    auto f2 = std::async(std::launch::async, [&] {
        httplib::Request r2;
        httplib::Response s2;
        middleware.process(r2, s2, [&](const httplib::Request&, httplib::Response&) {
            ready_p2.set_value();
            hold_p2.get_future().wait();
        });
    });

    ready_p1.get_future().wait();
    ready_p2.get_future().wait();

    EXPECT_EQ(middleware.active_connections(), 2);

    // 3rd concurrent request must be rejected with 503
    httplib::Request r3;
    httplib::Response s3;
    bool next3_invoked = false;
    middleware.process(r3, s3, [&next3_invoked](const httplib::Request&, httplib::Response&) { next3_invoked = true; });

    EXPECT_FALSE(next3_invoked);
    EXPECT_EQ(s3.get_header_value(ResourceLimiterMiddleware::k_header_retry_after),
              ResourceLimiterMiddleware::k_default_retry_after_seconds);
    verify_problem_details(s3, k_http_status_service_unavailable, "urn:securecloud:error:service_unavailable");

    // Unblock held requests
    hold_p1.set_value();
    hold_p2.set_value();
    f1.get();
    f2.get();

    EXPECT_EQ(middleware.active_connections(), 0);
}

TEST(ResourceLimiterMiddlewareTest, PropagatesRequestIdInProblemDetails) {
    auto limits = create_test_limits();
    ResourceLimiterMiddleware middleware(limits);

    httplib::Request req;
    req.headers.emplace(RequestIdMiddleware::k_request_id_header, "req-test-uuid-555");
    req.body = std::string(k_oversized_body_len, 'B');

    httplib::Response res;
    middleware.process(req, res, [](const httplib::Request&, httplib::Response&) {});

    EXPECT_EQ(res.status, k_http_status_payload_too_large);
    auto parsed = nlohmann::json::parse(res.body);
    EXPECT_EQ(parsed["request_id"], "req-test-uuid-555");
}

TEST(ResourceLimiterMiddlewareTest, RouterPipelineIntegration) {
    Router router;
    auto limits = create_test_limits();
    router.use(std::make_shared<ResourceLimiterMiddleware>(limits));

    router.post("/api/v1/data", [](const httplib::Request& req, httplib::Response& res) {
        res.status = k_http_status_ok;
        res.set_content("processed: " + req.body, "text/plain");
    });

    // 1. Valid request within bounds
    httplib::Request req_ok;
    req_ok.method = "POST";
    req_ok.path = "/api/v1/data";
    req_ok.body = "good-data";
    httplib::Response res_ok;
    router.handle(req_ok, res_ok);
    EXPECT_EQ(res_ok.status, k_http_status_ok);
    EXPECT_EQ(res_ok.body, "processed: good-data");

    // 2. Request exceeding body limit
    httplib::Request req_bad_body;
    req_bad_body.method = "POST";
    req_bad_body.path = "/api/v1/data";
    req_bad_body.body = std::string(k_oversized_body_len, 'X');
    httplib::Response res_bad_body;
    router.handle(req_bad_body, res_bad_body);
    EXPECT_EQ(res_bad_body.status, k_http_status_payload_too_large);
    verify_problem_details(res_bad_body, k_http_status_payload_too_large, "urn:securecloud:error:payload_too_large");

    // 3. Request exceeding header limit
    httplib::Request req_bad_header;
    req_bad_header.method = "POST";
    req_bad_header.path = "/api/v1/data";
    req_bad_header.headers.emplace("X-Huge", std::string(k_oversized_header_len, 'Y'));
    httplib::Response res_bad_header;
    router.handle(req_bad_header, res_bad_header);
    EXPECT_EQ(res_bad_header.status, k_http_status_header_too_large);
    verify_problem_details(res_bad_header, k_http_status_header_too_large, "urn:securecloud:error:header_too_large");
}

} // namespace
} // namespace securecloud::gateway::http
