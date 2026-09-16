#include <iostream>
#include <cstdlib>
#include "securecloud/common/version.hpp"

int main() {
    std::cout << "[Unit Test] Running SecureCloud baseline smoke test..." << std::endl;
    
    constexpr auto ver = securecloud::common::get_version_string();
    if (ver.empty()) {
        std::cerr << "[ERROR] Version string is empty!" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "[Unit Test] SecureCloud Version verified: " << ver << std::endl;
    return EXIT_SUCCESS;
}
