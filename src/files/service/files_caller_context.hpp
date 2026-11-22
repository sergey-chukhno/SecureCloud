#pragma once

#include <optional>
#include <string>

namespace securecloud::files::service {

/**
 * @brief Context propagated through Files domain services representing the caller identity
 * and distributed tracing correlation ID.
 */
struct FilesCallerContext {
    std::string user_id;
    std::string device_id;
    std::string correlation_id;
    std::optional<std::string> file_capability;
    std::optional<std::string> file_access_capability;
};

} // namespace securecloud::files::service
