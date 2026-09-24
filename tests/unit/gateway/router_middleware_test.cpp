#include "http/error_mapper.hpp"
#include "http/logging_middleware.hpp"
#include "http/middleware.hpp"
#include "http/request_id_middleware.hpp"
#include "http/router.hpp"

#include <grpcpp/support/status_code_enum.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace securecloud::gateway::http {
namespace {

constexpr int k_status_ok = 200;
constexpr int k_status_bad_request = 400;
constexpr int k_status_unauthorized = 401;
constexpr int k_status_forbidden = 403;
constexpr int k_status_not_found = 404;
constexpr int k_status_method_not_allowed = 405;
constexpr int k_status_internal_server_error = 500;
constexpr int k_status_service_unavailable = 503;
constexpr int k_status_gateway_timeout = 504;

constexpr size_t k_uuid_string_length = 36;
constexpr size_t k_uuid_version_pos = 14;
constexpr size_t k_expected_trace_steps = 5;

void verify_error_payload(const std::string& body, const std::string& expected_code, int expected_status,
                          int actual_status) {
    EXPECT_EQ(actual_status, expected_status);
    auto json = nlohmann::json::parse(body);
    ASSERT_TRUE(json.contains("error"));
    EXPECT_EQ(json["error"]["code"], expected_code);
    EXPECT_TRUE(json["error"].contains("message"));
    EXPECT_TRUE(json["error"].contains("request_id"));
}

void verify_route(Router& router, const std::string& method, const std::string& path,
                  const std::string& expected_body) {
    httplib::Request req;
    httplib::Response res;
    req.method = method;
    req.path = path;
    router.handle(req, res);
    EXPECT_EQ(res.status, k_status_ok);
    EXPECT_EQ(res.body, expected_body);
}

class TraceMiddleware : public Middleware {
  public:
    TraceMiddleware(std::string name, std::vector<std::string>& trace) : name_(std::move(name)), trace_(trace) {}

    void process(const httplib::Request& req, httplib::Response& res, const NextHandler& next) override {
        trace_.emplace_back(name_ + "_pre");
        next(req, res);
        trace_.emplace_back(name_ + "_post");
    }

  private:
    std::string name_;
    std::vector<std::string>& trace_;
};

TEST(RouterMiddlewareTest, RouterDispatchesExactMethodAndPath) {
    Router router;

    router.get("/v1/items", [](const httplib::Request&, httplib::Response& res) {
        res.status = k_status_ok;
        res.set_content("get_items", "text/plain");
    });
    router.post("/v1/items", [](const httplib::Request&, httplib::Response& res) {
        res.status = k_status_ok;
        res.set_content("post_items", "text/plain");
    });
    router.put("/v1/items", [](const httplib::Request&, httplib::Response& res) {
        res.status = k_status_ok;
        res.set_content("put_items", "text/plain");
    });
    router.del("/v1/items", [](const httplib::Request&, httplib::Response& res) {
        res.status = k_status_ok;
        res.set_content("delete_items", "text/plain");
    });

    verify_route(router, "GET", "/v1/items", "get_items");
    verify_route(router, "POST", "/v1/items", "post_items");
    verify_route(router, "PUT", "/v1/items", "put_items");
    verify_route(router, "DELETE", "/v1/items", "delete_items");
}

TEST(RouterMiddlewareTest, RouterReturns404ForUnregisteredRoute) {
    Router router;

    httplib::Request req;
    httplib::Response res;
    req.method = "GET";
    req.path = "/nonexistent/endpoint";

    router.handle(req, res);

    verify_error_payload(res.body, "NOT_FOUND", k_status_not_found, res.status);
}

TEST(RouterMiddlewareTest, RouterReturns405ForMethodMismatch) {
    Router router;

    router.post("/v1/upload", [](const httplib::Request&, httplib::Response& res) { res.status = k_status_ok; });

    httplib::Request req;
    httplib::Response res;
    req.method = "GET";
    req.path = "/v1/upload";

    router.handle(req, res);

    verify_error_payload(res.body, "METHOD_NOT_ALLOWED", k_status_method_not_allowed, res.status);
    ASSERT_TRUE(res.has_header("Allow"));
    EXPECT_EQ(res.get_header_value("Allow"), "POST");
}

TEST(RouterMiddlewareTest, RouterCatchesUnhandledException) {
    Router router;

    router.get("/panic", [](const httplib::Request&, httplib::Response&) {
        throw std::runtime_error("internal confidential database credentials leak");
    });

    httplib::Request req;
    httplib::Response res;
    req.method = "GET";
    req.path = "/panic";

    router.handle(req, res);

    verify_error_payload(res.body, "INTERNAL_ERROR", k_status_internal_server_error, res.status);
    // Crucial security invariant: confidential internal exception message must NOT leak
    EXPECT_EQ(res.body.find("confidential"), std::string::npos);
    EXPECT_EQ(res.body.find("database"), std::string::npos);
}

TEST(RouterMiddlewareTest, MiddlewareExecutesInDeterministicOrder) {
    Router router;
    std::vector<std::string> trace;

    router.use(std::make_shared<TraceMiddleware>("mw1", trace));
    router.use(std::make_shared<TraceMiddleware>("mw2", trace));

    router.get("/trace", [&trace](const httplib::Request&, httplib::Response& res) {
        trace.emplace_back("handler");
        res.status = k_status_ok;
    });

    httplib::Request req;
    httplib::Response res;
    req.method = "GET";
    req.path = "/trace";

    router.handle(req, res);

    ASSERT_EQ(trace.size(), k_expected_trace_steps);
    EXPECT_EQ(trace[0], "mw1_pre");
    EXPECT_EQ(trace[1], "mw2_pre");
    EXPECT_EQ(trace[2], "handler");
    EXPECT_EQ(trace[3], "mw2_post");
    EXPECT_EQ(trace[4], "mw1_post");
}

TEST(RouterMiddlewareTest, RequestIdMiddlewarePropagatesExistingId) {
    Router router;

    router.get("/echo-id", [](const httplib::Request&, httplib::Response& res) { res.status = k_status_ok; });

    httplib::Request req;
    httplib::Response res;
    req.method = "GET";
    req.path = "/echo-id";
    const std::string custom_id = "client-uuid-777-abc";
    req.set_header(RequestIdMiddleware::k_request_id_header, custom_id);

    router.handle(req, res);

    ASSERT_TRUE(res.has_header(RequestIdMiddleware::k_request_id_header));
    EXPECT_EQ(res.get_header_value(RequestIdMiddleware::k_request_id_header), custom_id);
}

TEST(RouterMiddlewareTest, RequestIdMiddlewareGeneratesValidUuidWhenMissing) {
    Router router;

    router.get("/new-id", [](const httplib::Request&, httplib::Response& res) { res.status = k_status_ok; });

    httplib::Request req;
    httplib::Response res;
    req.method = "GET";
    req.path = "/new-id";

    router.handle(req, res);

    ASSERT_TRUE(res.has_header(RequestIdMiddleware::k_request_id_header));
    std::string gen_id = res.get_header_value(RequestIdMiddleware::k_request_id_header);
    EXPECT_EQ(gen_id.length(), k_uuid_string_length);
    EXPECT_EQ(gen_id[k_uuid_version_pos], '4'); // UUIDv4
}

TEST(RouterMiddlewareTest, ErrorMapperGrpcStatusTranslation) {
    EXPECT_EQ(ErrorMapper::grpc_to_http_status(grpc::StatusCode::OK), k_status_ok);
    EXPECT_EQ(ErrorMapper::grpc_to_http_status(grpc::StatusCode::INVALID_ARGUMENT), k_status_bad_request);
    EXPECT_EQ(ErrorMapper::grpc_to_http_status(grpc::StatusCode::UNAUTHENTICATED), k_status_unauthorized);
    EXPECT_EQ(ErrorMapper::grpc_to_http_status(grpc::StatusCode::PERMISSION_DENIED), k_status_forbidden);
    EXPECT_EQ(ErrorMapper::grpc_to_http_status(grpc::StatusCode::NOT_FOUND), k_status_not_found);
    EXPECT_EQ(ErrorMapper::grpc_to_http_status(grpc::StatusCode::UNAVAILABLE), k_status_service_unavailable);
    EXPECT_EQ(ErrorMapper::grpc_to_http_status(grpc::StatusCode::DEADLINE_EXCEEDED), k_status_gateway_timeout);

    EXPECT_EQ(ErrorMapper::grpc_to_error_code(grpc::StatusCode::NOT_FOUND), "NOT_FOUND");
    EXPECT_EQ(ErrorMapper::grpc_to_error_code(grpc::StatusCode::UNAUTHENTICATED), "UNAUTHENTICATED");
    EXPECT_EQ(ErrorMapper::grpc_to_error_code(grpc::StatusCode::UNAVAILABLE), "SERVICE_UNAVAILABLE");
}

TEST(RouterMiddlewareTest, LoggingMiddlewareRouteSensitivity) {
    EXPECT_TRUE(LoggingMiddleware::is_sensitive_auth_route("/auth/login"));
    EXPECT_TRUE(LoggingMiddleware::is_sensitive_auth_route("/api/v1/auth/tokens"));
    EXPECT_FALSE(LoggingMiddleware::is_sensitive_auth_route("/api/v1/files/upload"));
    EXPECT_FALSE(LoggingMiddleware::is_sensitive_auth_route("/health"));

    std::string captured_log;
    LoggingMiddleware logging([&captured_log](const std::string& line) { captured_log = line; });

    httplib::Request req;
    httplib::Response res;
    req.method = "GET";
    req.path = "/api/v1/status";
    res.status = k_status_ok;

    logging.process(req, res, [](const httplib::Request&, httplib::Response&) {});

    EXPECT_FALSE(captured_log.empty());
    EXPECT_NE(captured_log.find("GET /api/v1/status -> 200"), std::string::npos);
}

} // namespace
} // namespace securecloud::gateway::http
