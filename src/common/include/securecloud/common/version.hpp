#pragma once

#include <string_view>

namespace securecloud::common {

struct Version {
    static constexpr unsigned int major = 0;
    static constexpr unsigned int minor = 1;
    static constexpr unsigned int patch = 0;
    static constexpr std::string_view string_val = "0.1.0-dev";
};

[[nodiscard]] constexpr std::string_view get_version_string() noexcept {
    return Version::string_val;
}

[[nodiscard]] std::string_view get_full_version_banner() noexcept;

} // namespace securecloud::common
