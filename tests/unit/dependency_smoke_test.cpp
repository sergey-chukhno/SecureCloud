#include "securecloud/common/version.hpp"

#include <cstdlib>
#include <iostream>

int main() {
    std::cout << "[Dependency Smoke Test] Verifying dependency management and discovery pipeline...\n";

    constexpr auto version_str = securecloud::common::get_version_string();
    if (version_str.empty()) {
        std::cerr << "[ERROR] Dependency discovery smoke test failed: version string unavailable\n";
        return EXIT_FAILURE;
    }

    std::cout << "[Dependency Smoke Test] Dependency discovery pipeline verified successfully (Version: " << version_str
              << ")\n";
    return EXIT_SUCCESS;
}
