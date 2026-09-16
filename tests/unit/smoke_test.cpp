#include "securecloud/common/version.hpp"

#include <cstdlib>
#include <iostream>

int main() {
    std::cout << "[Unit Test] Running SecureCloud baseline smoke test...\n";

    constexpr auto ver = securecloud::common::get_version_string();
    if (ver.empty()) {
        std::cerr << "[ERROR] Version string is empty!\n";
        return EXIT_FAILURE;
    }

    std::cout << "[Unit Test] SecureCloud Version verified: " << ver << "\n";
    return EXIT_SUCCESS;
}
