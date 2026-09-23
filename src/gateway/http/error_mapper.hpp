#pragma once

#include <grpcpp/support/status_code_enum.h>
#include <string>
#include <string_view>

namespace httplib {
struct Response;
}

namespace securecloud::gateway::http {

class ErrorMapper {
  public:
    [[nodiscard]] static int grpc_to_http_status(::grpc::StatusCode status_code) noexcept;
    [[nodiscard]] static std::string_view grpc_to_error_code(::grpc::StatusCode status_code);

    [[nodiscard]] static std::string format_error_json(const std::string& code, const std::string& message,
                                                       const std::string& request_id = "");

    static void write_error(httplib::Response& res, int http_status, const std::string& code,
                            const std::string& message, const std::string& request_id = "");
};

} // namespace securecloud::gateway::http
