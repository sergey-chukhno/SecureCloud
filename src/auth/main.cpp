#include "securecloud/common/version.hpp"

#include <iostream>

int main() {
    std::cout << "[SecureCloud Auth] Starting Auth Service v" << securecloud::common::get_version_string() << "\n";
    return 0;
}
