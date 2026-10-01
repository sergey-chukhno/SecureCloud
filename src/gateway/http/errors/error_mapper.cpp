#include "http/errors/error_mapper.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <utility>

namespace securecloud::gateway::http {
namespace {

constexpr int k_status_ok = 200;
constexpr int k_status_bad_request = 400;
constexpr int k_status_unauthorized = 401;
constexpr int k_status_forbidden = 403;
constexpr int k_status_not_found = 404;
constexpr int k_status_conflict = 409;
constexpr int k_status_precondition_failed = 412;
constexpr int k_status_too_many_requests = 429;
constexpr int k_status_client_closed_request = 499;
constexpr int k_status_internal_server_error = 500;
constexpr int k_status_not_implemented = 501;
constexpr int k_status_service_unavailable = 503;
constexpr int k_status_gateway_timeout = 504;

constexpr const char* k_content_type_json = "application/json";

constexpr std::string_view k_type_ok = "https://securecloud.internal/errors/ok";
constexpr std::string_view k_type_bad_request = "https://securecloud.internal/errors/bad-request";
constexpr std::string_view k_type_unauthenticated = "https://securecloud.internal/errors/unauthenticated";
constexpr std::string_view k_type_forbidden = "https://securecloud.internal/errors/forbidden";
constexpr std::string_view k_type_not_found = "https://securecloud.internal/errors/not-found";
constexpr std::string_view k_type_conflict = "https://securecloud.internal/errors/conflict";
constexpr std::string_view k_type_precondition_failed = "https://securecloud.internal/errors/precondition-failed";
constexpr std::string_view k_type_rate_limited = "https://securecloud.internal/errors/rate-limited";
constexpr std::string_view k_type_client_cancelled = "https://securecloud.internal/errors/client-cancelled";
constexpr std::string_view k_type_internal_error = "https://securecloud.internal/errors/internal-error";
constexpr std::string_view k_type_not_implemented = "https://securecloud.internal/errors/not-implemented";
constexpr std::string_view k_type_service_unavailable = "https://securecloud.internal/errors/service-unavailable";
constexpr std::string_view k_type_gateway_timeout = "https://securecloud.internal/errors/gateway-timeout";

} // namespace

int ErrorMapper::grpc_to_http_status(::grpc::StatusCode status_code) noexcept {
    switch (status_code) {
    case ::grpc::StatusCode::OK:
        return k_status_ok;
    case ::grpc::StatusCode::CANCELLED:
        return k_status_client_closed_request;
    case ::grpc::StatusCode::UNKNOWN:
        return k_status_internal_server_error;
    case ::grpc::StatusCode::INVALID_ARGUMENT:
        return k_status_bad_request;
    case ::grpc::StatusCode::DEADLINE_EXCEEDED:
        return k_status_gateway_timeout;
    case ::grpc::StatusCode::NOT_FOUND:
        return k_status_not_found;
    case ::grpc::StatusCode::ALREADY_EXISTS:
        return k_status_conflict;
    case ::grpc::StatusCode::PERMISSION_DENIED:
        return k_status_forbidden;
    case ::grpc::StatusCode::RESOURCE_EXHAUSTED:
        return k_status_too_many_requests;
    case ::grpc::StatusCode::FAILED_PRECONDITION:
        return k_status_precondition_failed;
    case ::grpc::StatusCode::ABORTED:
        return k_status_conflict;
    case ::grpc::StatusCode::OUT_OF_RANGE:
        return k_status_bad_request;
    case ::grpc::StatusCode::UNIMPLEMENTED:
        return k_status_not_implemented;
    case ::grpc::StatusCode::INTERNAL:
        return k_status_internal_server_error;
    case ::grpc::StatusCode::UNAVAILABLE:
        return k_status_service_unavailable;
    case ::grpc::StatusCode::DATA_LOSS:
        return k_status_internal_server_error;
    case ::grpc::StatusCode::UNAUTHENTICATED:
        return k_status_unauthorized;
    default:
        return k_status_internal_server_error;
    }
}

std::string_view ErrorMapper::grpc_to_error_code(::grpc::StatusCode status_code) noexcept {
    switch (status_code) {
    case ::grpc::StatusCode::OK:
        return "OK";
    case ::grpc::StatusCode::CANCELLED:
        return "CLIENT_CANCELLED";
    case ::grpc::StatusCode::UNKNOWN:
        return "INTERNAL_ERROR";
    case ::grpc::StatusCode::INVALID_ARGUMENT:
        return "INVALID_ARGUMENT";
    case ::grpc::StatusCode::DEADLINE_EXCEEDED:
        return "GATEWAY_TIMEOUT";
    case ::grpc::StatusCode::NOT_FOUND:
        return "NOT_FOUND";
    case ::grpc::StatusCode::ALREADY_EXISTS:
        return "ALREADY_EXISTS";
    case ::grpc::StatusCode::PERMISSION_DENIED:
        return "PERMISSION_DENIED";
    case ::grpc::StatusCode::RESOURCE_EXHAUSTED:
        return "RESOURCE_EXHAUSTED";
    case ::grpc::StatusCode::FAILED_PRECONDITION:
        return "FAILED_PRECONDITION";
    case ::grpc::StatusCode::ABORTED:
        return "CONFLICT";
    case ::grpc::StatusCode::OUT_OF_RANGE:
        return "OUT_OF_RANGE";
    case ::grpc::StatusCode::UNIMPLEMENTED:
        return "NOT_IMPLEMENTED";
    case ::grpc::StatusCode::INTERNAL:
        return "INTERNAL_ERROR";
    case ::grpc::StatusCode::UNAVAILABLE:
        return "SERVICE_UNAVAILABLE";
    case ::grpc::StatusCode::DATA_LOSS:
        return "DATA_LOSS";
    case ::grpc::StatusCode::UNAUTHENTICATED:
        return "UNAUTHENTICATED";
    default:
        return "INTERNAL_ERROR";
    }
}

std::string_view ErrorMapper::grpc_to_problem_type(::grpc::StatusCode status_code) noexcept {
    switch (status_code) {
    case ::grpc::StatusCode::OK:
        return k_type_ok;
    case ::grpc::StatusCode::CANCELLED:
        return k_type_client_cancelled;
    case ::grpc::StatusCode::UNKNOWN:
        return k_type_internal_error;
    case ::grpc::StatusCode::INVALID_ARGUMENT:
        return k_type_bad_request;
    case ::grpc::StatusCode::DEADLINE_EXCEEDED:
        return k_type_gateway_timeout;
    case ::grpc::StatusCode::NOT_FOUND:
        return k_type_not_found;
    case ::grpc::StatusCode::ALREADY_EXISTS:
        return k_type_conflict;
    case ::grpc::StatusCode::PERMISSION_DENIED:
        return k_type_forbidden;
    case ::grpc::StatusCode::RESOURCE_EXHAUSTED:
        return k_type_rate_limited;
    case ::grpc::StatusCode::FAILED_PRECONDITION:
        return k_type_precondition_failed;
    case ::grpc::StatusCode::ABORTED:
        return k_type_conflict;
    case ::grpc::StatusCode::OUT_OF_RANGE:
        return k_type_bad_request;
    case ::grpc::StatusCode::UNIMPLEMENTED:
        return k_type_not_implemented;
    case ::grpc::StatusCode::INTERNAL:
        return k_type_internal_error;
    case ::grpc::StatusCode::UNAVAILABLE:
        return k_type_service_unavailable;
    case ::grpc::StatusCode::DATA_LOSS:
        return k_type_internal_error;
    case ::grpc::StatusCode::UNAUTHENTICATED:
        return k_type_unauthenticated;
    default:
        return k_type_internal_error;
    }
}

std::string_view ErrorMapper::grpc_to_problem_title(::grpc::StatusCode status_code) noexcept {
    switch (status_code) {
    case ::grpc::StatusCode::OK:
        return "OK";
    case ::grpc::StatusCode::CANCELLED:
        return "Client Closed Request";
    case ::grpc::StatusCode::UNKNOWN:
        return "Internal Server Error";
    case ::grpc::StatusCode::INVALID_ARGUMENT:
        return "Bad Request";
    case ::grpc::StatusCode::DEADLINE_EXCEEDED:
        return "Gateway Timeout";
    case ::grpc::StatusCode::NOT_FOUND:
        return "Not Found";
    case ::grpc::StatusCode::ALREADY_EXISTS:
        return "Conflict";
    case ::grpc::StatusCode::PERMISSION_DENIED:
        return "Forbidden";
    case ::grpc::StatusCode::RESOURCE_EXHAUSTED:
        return "Too Many Requests";
    case ::grpc::StatusCode::FAILED_PRECONDITION:
        return "Precondition Failed";
    case ::grpc::StatusCode::ABORTED:
        return "Conflict";
    case ::grpc::StatusCode::OUT_OF_RANGE:
        return "Bad Request";
    case ::grpc::StatusCode::UNIMPLEMENTED:
        return "Not Implemented";
    case ::grpc::StatusCode::INTERNAL:
        return "Internal Server Error";
    case ::grpc::StatusCode::UNAVAILABLE:
        return "Service Unavailable";
    case ::grpc::StatusCode::DATA_LOSS:
        return "Data Loss";
    case ::grpc::StatusCode::UNAUTHENTICATED:
        return "Unauthorized";
    default:
        return "Internal Server Error";
    }
}

std::string_view ErrorMapper::http_status_to_default_type(int http_status) noexcept {
    switch (http_status) {
    case k_status_bad_request:
        return k_type_bad_request;
    case k_status_unauthorized:
        return k_type_unauthenticated;
    case k_status_forbidden:
        return k_type_forbidden;
    case k_status_not_found:
        return k_type_not_found;
    case k_status_conflict:
        return k_type_conflict;
    case k_status_precondition_failed:
        return k_type_precondition_failed;
    case k_status_too_many_requests:
        return k_type_rate_limited;
    case k_status_client_closed_request:
        return k_type_client_cancelled;
    case k_status_not_implemented:
        return k_type_not_implemented;
    case k_status_service_unavailable:
        return k_type_service_unavailable;
    case k_status_gateway_timeout:
        return k_type_gateway_timeout;
    case k_status_internal_server_error:
    default:
        return k_type_internal_error;
    }
}

std::string_view ErrorMapper::http_status_to_default_title(int http_status) noexcept {
    switch (http_status) {
    case k_status_bad_request:
        return "Bad Request";
    case k_status_unauthorized:
        return "Unauthorized";
    case k_status_forbidden:
        return "Forbidden";
    case k_status_not_found:
        return "Not Found";
    case k_status_conflict:
        return "Conflict";
    case k_status_precondition_failed:
        return "Precondition Failed";
    case k_status_too_many_requests:
        return "Too Many Requests";
    case k_status_client_closed_request:
        return "Client Closed Request";
    case k_status_not_implemented:
        return "Not Implemented";
    case k_status_service_unavailable:
        return "Service Unavailable";
    case k_status_gateway_timeout:
        return "Gateway Timeout";
    case k_status_internal_server_error:
    default:
        return "Internal Server Error";
    }
}

std::string ErrorMapper::format_problem_details(int http_status, std::string_view type_uri, std::string_view title,
                                                std::string_view detail, std::string_view error_code,
                                                std::string_view request_id) {
    nlohmann::json root;
    root["type"] = std::string(type_uri.empty() ? http_status_to_default_type(http_status) : type_uri);
    root["title"] = std::string(title.empty() ? http_status_to_default_title(http_status) : title);
    root["status"] = http_status;
    root["detail"] = std::string(detail);

    if (!request_id.empty()) {
        root["request_id"] = std::string(request_id);
    }

    nlohmann::json err_obj = nlohmann::json::object();
    err_obj["code"] = std::string(error_code.empty() ? "INTERNAL_ERROR" : error_code);
    err_obj["message"] = std::string(detail);
    if (!request_id.empty()) {
        err_obj["request_id"] = std::string(request_id);
    }
    root["error"] = std::move(err_obj);

    return root.dump();
}

std::string ErrorMapper::format_error_json(const std::string& code, const std::string& message,
                                           const std::string& request_id, int http_status) {
    const auto type_uri = http_status_to_default_type(http_status);
    const auto title = http_status_to_default_title(http_status);
    return format_problem_details(http_status, type_uri, title, message, code, request_id);
}

void ErrorMapper::write_error(httplib::Response& res, int http_status, const std::string& code,
                              const std::string& message, const std::string& request_id) {
    res.status = http_status;
    res.set_content(format_error_json(code, message, request_id, http_status), k_content_type_json);
}

void ErrorMapper::write_grpc_error(httplib::Response& res, ::grpc::StatusCode status_code, const std::string& message,
                                   const std::string& request_id) {
    const int http_status = grpc_to_http_status(status_code);
    const auto error_code = grpc_to_error_code(status_code);
    const auto type_uri = grpc_to_problem_type(status_code);
    const auto title = grpc_to_problem_title(status_code);

    res.status = http_status;
    res.set_content(format_problem_details(http_status, type_uri, title, message, error_code, request_id),
                    k_content_type_json);
}

} // namespace securecloud::gateway::http
