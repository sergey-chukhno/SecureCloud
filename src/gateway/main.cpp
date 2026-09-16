#include "securecloud/common/version.hpp"

#include <iostream>

int main() {
    std::cout << "[SecureCloud Gateway] Starting Gateway v" << securecloud::common::get_version_string() << "\n";
    return 0;
}
