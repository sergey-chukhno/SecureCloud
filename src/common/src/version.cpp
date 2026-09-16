#include "securecloud/common/version.hpp"

namespace securecloud::common {

std::string_view get_full_version_banner() noexcept {
    return "SecureCloud Platform v0.1.0-dev (C++20 baseline)";
}

} // namespace securecloud::common
