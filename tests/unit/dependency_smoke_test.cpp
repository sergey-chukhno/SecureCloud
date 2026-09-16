#include <iostream>
#include <cstdlib>
#include "securecloud/common/version.hpp"

int main() {
    std::cout << "[Dependency Smoke Test] Verifying dependency management and discovery pipeline..." << std::endl;
    
    constexpr auto version_str = securecloud::common::get_version_string();
    if (version_str.empty()) {
        std::cerr << "[ERROR] Dependency discovery smoke test failed: version string unavailable" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "[Dependency Smoke Test] Dependency discovery pipeline verified successfully (Version: " 
              << version_str << ")" << std::endl;
    return EXIT_SUCCESS;
}
