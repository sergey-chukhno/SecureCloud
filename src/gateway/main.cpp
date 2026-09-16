#include <iostream>
#include "securecloud/common/version.hpp"

int main() {
    std::cout << "[SecureCloud Gateway] Starting API Gateway Service v" 
              << securecloud::common::get_version_string() << std::endl;
    return 0;
}
