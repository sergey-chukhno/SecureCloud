#include "securecloud/common/version.hpp"

#include <iostream>

int main() {
    std::cout << "[SecureCloud Files] Starting Files Service v" << securecloud::common::get_version_string() << "\n";
    return 0;
}
