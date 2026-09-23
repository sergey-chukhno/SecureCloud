#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "http/error_mapper.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

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
constexpr int k_status_internal_server_error = 500;
constexpr int k_status_not_implemented = 501;
constexpr int k_status_service_unavailable = 503;
constexpr int k_status_gateway_timeout = 504;

constexpr const char* k_content_type_json = "application/json";

} // namespace

int ErrorMapper::grpc_to_http_status(grpc::StatusCode status_code) noexcept {
    switch (status_code) {
    case grpc::StatusCode::OK:
        return k_status_ok;
    case grpc::StatusCode::INVALID_ARGUMENT:
        return k_status_bad_request;
    case grpc::StatusCode::UNAUTHENTICATED:
        return k_status_unauthorized;
    case grpc::StatusCode::PERMISSION_DENIED:
        return k_status_forbidden;
    case grpc::StatusCode::NOT_FOUND:
        return k_status_not_found;
    case grpc::StatusCode::ALREADY_EXISTS:
        return k_status_conflict;
    case grpc::StatusCode::FAILED_PRECONDITION:
        return k_status_precondition_failed;
    case grpc::StatusCode::RESOURCE_EXHAUSTED:
        return k_status_too_many_requests;
    case grpc::StatusCode::UNIMPLEMENTED:
        return k_status_not_implemented;
    case grpc::StatusCode::UNAVAILABLE:
        return k_status_service_unavailable;
    case grpc::StatusCode::DEADLINE_EXCEEDED:
        return k_status_gateway_timeout;
    default:
        return k_status_internal_server_error;
    }
}

std::string_view ErrorMapper::grpc_to_error_code(grpc::StatusCode status_code) {
    switch (status_code) {
    case grpc::StatusCode::OK:
        return "OK";
    case grpc::StatusCode::INVALID_ARGUMENT:
        return "INVALID_ARGUMENT";
    case grpc::StatusCode::UNAUTHENTICATED:
        return "UNAUTHENTICATED";
    case grpc::StatusCode::PERMISSION_DENIED:
        return "PERMISSION_DENIED";
    case grpc::StatusCode::NOT_FOUND:
        return "NOT_FOUND";
    case grpc::StatusCode::ALREADY_EXISTS:
        return "ALREADY_EXISTS";
    case grpc::StatusCode::FAILED_PRECONDITION:
        return "FAILED_PRECONDITION";
    case grpc::StatusCode::RESOURCE_EXHAUSTED:
        return "RESOURCE_EXHAUSTED";
    case grpc::StatusCode::UNIMPLEMENTED:
        return "NOT_IMPLEMENTED";
    case grpc::StatusCode::UNAVAILABLE:
        return "SERVICE_UNAVAILABLE";
    case grpc::StatusCode::DEADLINE_EXCEEDED:
        return "GATEWAY_TIMEOUT";
    default:
        return "INTERNAL_ERROR";
    }
}

std::string ErrorMapper::format_error_json(const std::string& code, const std::string& message,
                                           const std::string& request_id) {
    nlohmann::json root;
    root["error"] = nlohmann::json::object();
    root["error"]["code"] = code;
    root["error"]["message"] = message;
    if (!request_id.empty()) {
        root["error"]["request_id"] = request_id;
    }
    return root.dump();
}

void ErrorMapper::write_error(httplib::Response& res, int http_status, const std::string& code,
                              const std::string& message, const std::string& request_id) {
    res.status = http_status;
    res.set_content(format_error_json(code, message, request_id), k_content_type_json);
}

} // namespace securecloud::gateway::http
