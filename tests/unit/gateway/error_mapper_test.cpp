#include "http/error_mapper.hpp"

#include <grpcpp/support/status_code_enum.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace securecloud::gateway::http {
namespace {

TEST(ErrorMapperTest, AllSixteenGrpcStatusCodesMapDeterministically) {
    const std::vector<::grpc::StatusCode> codes = {
        ::grpc::StatusCode::OK,
        ::grpc::StatusCode::CANCELLED,
        ::grpc::StatusCode::UNKNOWN,
        ::grpc::StatusCode::INVALID_ARGUMENT,
        ::grpc::StatusCode::DEADLINE_EXCEEDED,
        ::grpc::StatusCode::NOT_FOUND,
        ::grpc::StatusCode::ALREADY_EXISTS,
        ::grpc::StatusCode::PERMISSION_DENIED,
        ::grpc::StatusCode::RESOURCE_EXHAUSTED,
        ::grpc::StatusCode::FAILED_PRECONDITION,
        ::grpc::StatusCode::ABORTED,
        ::grpc::StatusCode::OUT_OF_RANGE,
        ::grpc::StatusCode::UNIMPLEMENTED,
        ::grpc::StatusCode::INTERNAL,
        ::grpc::StatusCode::UNAVAILABLE,
        ::grpc::StatusCode::DATA_LOSS,
        ::grpc::StatusCode::UNAUTHENTICATED,
    };

    for (const auto code : codes) {
        const int http_status = ErrorMapper::grpc_to_http_status(code);
        EXPECT_GE(http_status, 200);
        EXPECT_LE(http_status, 599);

        const auto error_code = ErrorMapper::grpc_to_error_code(code);
        EXPECT_FALSE(error_code.empty());

        const auto problem_type = ErrorMapper::grpc_to_problem_type(code);
        EXPECT_FALSE(problem_type.empty());
        EXPECT_TRUE(problem_type.starts_with("https://securecloud.internal/errors/"));

        const auto problem_title = ErrorMapper::grpc_to_problem_title(code);
        EXPECT_FALSE(problem_title.empty());
    }
}

TEST(ErrorMapperTest, CancelledMapsTo499ClientClosedRequest) {
    EXPECT_EQ(ErrorMapper::grpc_to_http_status(::grpc::StatusCode::CANCELLED), 499);
    EXPECT_EQ(ErrorMapper::grpc_to_error_code(::grpc::StatusCode::CANCELLED), "CLIENT_CANCELLED");
    EXPECT_EQ(ErrorMapper::grpc_to_problem_type(::grpc::StatusCode::CANCELLED),
              "https://securecloud.internal/errors/client-cancelled");
    EXPECT_EQ(ErrorMapper::grpc_to_problem_title(::grpc::StatusCode::CANCELLED), "Client Closed Request");
}

TEST(ErrorMapperTest, DeadlineExceededMapsTo504GatewayTimeout) {
    EXPECT_EQ(ErrorMapper::grpc_to_http_status(::grpc::StatusCode::DEADLINE_EXCEEDED), 504);
    EXPECT_EQ(ErrorMapper::grpc_to_error_code(::grpc::StatusCode::DEADLINE_EXCEEDED), "GATEWAY_TIMEOUT");
    EXPECT_EQ(ErrorMapper::grpc_to_problem_type(::grpc::StatusCode::DEADLINE_EXCEEDED),
              "https://securecloud.internal/errors/gateway-timeout");
    EXPECT_EQ(ErrorMapper::grpc_to_problem_title(::grpc::StatusCode::DEADLINE_EXCEEDED), "Gateway Timeout");
}

TEST(ErrorMapperTest, UnavailableMapsTo503ServiceUnavailable) {
    EXPECT_EQ(ErrorMapper::grpc_to_http_status(::grpc::StatusCode::UNAVAILABLE), 503);
    EXPECT_EQ(ErrorMapper::grpc_to_error_code(::grpc::StatusCode::UNAVAILABLE), "SERVICE_UNAVAILABLE");
    EXPECT_EQ(ErrorMapper::grpc_to_problem_type(::grpc::StatusCode::UNAVAILABLE),
              "https://securecloud.internal/errors/service-unavailable");
    EXPECT_EQ(ErrorMapper::grpc_to_problem_title(::grpc::StatusCode::UNAVAILABLE), "Service Unavailable");
}

TEST(ErrorMapperTest, UnauthenticatedAndPermissionDeniedMapTo401And403) {
    EXPECT_EQ(ErrorMapper::grpc_to_http_status(::grpc::StatusCode::UNAUTHENTICATED), 401);
    EXPECT_EQ(ErrorMapper::grpc_to_error_code(::grpc::StatusCode::UNAUTHENTICATED), "UNAUTHENTICATED");
    EXPECT_EQ(ErrorMapper::grpc_to_problem_type(::grpc::StatusCode::UNAUTHENTICATED),
              "https://securecloud.internal/errors/unauthenticated");

    EXPECT_EQ(ErrorMapper::grpc_to_http_status(::grpc::StatusCode::PERMISSION_DENIED), 403);
    EXPECT_EQ(ErrorMapper::grpc_to_error_code(::grpc::StatusCode::PERMISSION_DENIED), "PERMISSION_DENIED");
    EXPECT_EQ(ErrorMapper::grpc_to_problem_type(::grpc::StatusCode::PERMISSION_DENIED),
              "https://securecloud.internal/errors/forbidden");
}

TEST(ErrorMapperTest, FormatProblemDetailsProducesValidRfc7807Json) {
    const std::string json_str = ErrorMapper::format_problem_details(
        504, "https://securecloud.internal/errors/gateway-timeout", "Gateway Timeout",
        "Downstream Auth service call exceeded deadline", "GATEWAY_TIMEOUT", "req-test-999");

    const auto root = nlohmann::json::parse(json_str);
    EXPECT_EQ(root["type"], "https://securecloud.internal/errors/gateway-timeout");
    EXPECT_EQ(root["title"], "Gateway Timeout");
    EXPECT_EQ(root["status"], 504);
    EXPECT_EQ(root["detail"], "Downstream Auth service call exceeded deadline");
    EXPECT_EQ(root["request_id"], "req-test-999");

    // Legacy error object assertions
    ASSERT_TRUE(root.contains("error"));
    EXPECT_EQ(root["error"]["code"], "GATEWAY_TIMEOUT");
    EXPECT_EQ(root["error"]["message"], "Downstream Auth service call exceeded deadline");
    EXPECT_EQ(root["error"]["request_id"], "req-test-999");
}

TEST(ErrorMapperTest, RequestIdOmittedWhenEmpty) {
    const std::string json_str = ErrorMapper::format_problem_details(
        400, "https://securecloud.internal/errors/bad-request", "Bad Request", "Missing parameter", "BAD_REQUEST", "");

    const auto root = nlohmann::json::parse(json_str);
    EXPECT_FALSE(root.contains("request_id"));
    EXPECT_FALSE(root["error"].contains("request_id"));
}

TEST(ErrorMapperTest, FormatErrorJsonUsesCorrectDefaultTypeAndTitle) {
    const std::string json_404 =
        ErrorMapper::format_error_json("USER_NOT_FOUND", "User does not exist", "req-404", 404);
    const auto root_404 = nlohmann::json::parse(json_404);
    EXPECT_EQ(root_404["status"], 404);
    EXPECT_EQ(root_404["type"], "https://securecloud.internal/errors/not-found");
    EXPECT_EQ(root_404["title"], "Not Found");
    EXPECT_EQ(root_404["detail"], "User does not exist");
    EXPECT_EQ(root_404["error"]["code"], "USER_NOT_FOUND");
}

TEST(ErrorMapperTest, WriteErrorSetsHttpStatusAndContent) {
    httplib::Response res;
    ErrorMapper::write_error(res, 503, "SERVICE_UNAVAILABLE", "Downstream service offline", "req-write-1");

    EXPECT_EQ(res.status, 503);
    EXPECT_EQ(res.get_header_value("Content-Type"), "application/json");

    const auto root = nlohmann::json::parse(res.body);
    EXPECT_EQ(root["status"], 503);
    EXPECT_EQ(root["error"]["code"], "SERVICE_UNAVAILABLE");
    EXPECT_EQ(root["request_id"], "req-write-1");
}

TEST(ErrorMapperTest, WriteGrpcErrorMapsStatusAndWritesResponse) {
    httplib::Response res;
    ErrorMapper::write_grpc_error(res, ::grpc::StatusCode::RESOURCE_EXHAUSTED, "Rate limit exceeded", "req-rate-1");

    EXPECT_EQ(res.status, 429);
    EXPECT_EQ(res.get_header_value("Content-Type"), "application/json");

    const auto root = nlohmann::json::parse(res.body);
    EXPECT_EQ(root["status"], 429);
    EXPECT_EQ(root["type"], "https://securecloud.internal/errors/rate-limited");
    EXPECT_EQ(root["title"], "Too Many Requests");
    EXPECT_EQ(root["detail"], "Rate limit exceeded");
    EXPECT_EQ(root["error"]["code"], "RESOURCE_EXHAUSTED");
}

TEST(ErrorMapperTest, UnknownStatusCodeDefaultsTo500InternalError) {
    const auto invalid_code =
        static_cast<::grpc::StatusCode>(static_cast<int>(::grpc::StatusCode::UNAUTHENTICATED) + 1);
    EXPECT_EQ(ErrorMapper::grpc_to_http_status(invalid_code), 500);
    EXPECT_EQ(ErrorMapper::grpc_to_error_code(invalid_code), "INTERNAL_ERROR");
    EXPECT_EQ(ErrorMapper::grpc_to_problem_type(invalid_code), "https://securecloud.internal/errors/internal-error");
    EXPECT_EQ(ErrorMapper::grpc_to_problem_title(invalid_code), "Internal Server Error");
}

} // namespace
} // namespace securecloud::gateway::http
