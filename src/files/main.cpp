#include "securecloud/common/version.hpp"

#include <iostream>
#include <string_view>

namespace {
constexpr std::string_view service_name = "files";
constexpr std::string_view service_display_name = "Files Service";
} // namespace

int main() {
    std::cout << "[SecureCloud] Starting " << service_display_name << " (" << service_name << ") v"
              << securecloud::common::get_version_string() << "\n";
    return 0;
}
