#pragma once

#include <grpcpp/support/status_code_enum.h>
#include <string>
#include <string_view>

namespace httplib {
struct Response;
}

namespace securecloud::gateway::http {

/**
 * @brief Translates downstream gRPC status codes and perimeter errors into standardized
 * RFC 7807 Problem Details HTTP responses (GW-008-T01).
 *
 * Preserves a backward-compatible "error" JSON object for legacy clients while conforming
 * strictly to RFC 7807 ("type", "title", "status", "detail", "request_id").
 */
class ErrorMapper {
  public:
    [[nodiscard]] static int grpc_to_http_status(::grpc::StatusCode status_code) noexcept;
    [[nodiscard]] static std::string_view grpc_to_error_code(::grpc::StatusCode status_code) noexcept;
    [[nodiscard]] static std::string_view grpc_to_problem_type(::grpc::StatusCode status_code) noexcept;
    [[nodiscard]] static std::string_view grpc_to_problem_title(::grpc::StatusCode status_code) noexcept;

    [[nodiscard]] static std::string_view http_status_to_default_type(int http_status) noexcept;
    [[nodiscard]] static std::string_view http_status_to_default_title(int http_status) noexcept;

    /**
     * @brief Formats full RFC 7807 problem details JSON with embedded backward-compatible error block.
     */
    [[nodiscard]] static std::string format_problem_details(int http_status, std::string_view type_uri,
                                                            std::string_view title, std::string_view detail,
                                                            std::string_view error_code,
                                                            std::string_view request_id = "");

    /**
     * @brief Formats error JSON adhering to RFC 7807 problem details schema with backward compatibility.
     */
    [[nodiscard]] static std::string format_error_json(const std::string& code, const std::string& message,
                                                       const std::string& request_id = "", int http_status = 500);

    /**
     * @brief Writes RFC 7807 problem details payload directly to an HTTP response.
     */
    static void write_error(httplib::Response& res, int http_status, const std::string& code,
                            const std::string& message, const std::string& request_id = "");

    /**
     * @brief Translates a downstream gRPC status code directly into an RFC 7807 HTTP response.
     */
    static void write_grpc_error(httplib::Response& res, ::grpc::StatusCode status_code, const std::string& message,
                                 const std::string& request_id = "");
};

} // namespace securecloud::gateway::http
