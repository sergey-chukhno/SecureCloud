#include <iostream>
#include "securecloud/common/version.hpp"

int main() {
    std::cout << "[SecureCloud Messaging] Starting Messaging Service v" 
              << securecloud::common::get_version_string() << std::endl;
    return 0;
}
