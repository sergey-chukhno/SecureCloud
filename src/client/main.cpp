#include <iostream>
#include "securecloud/common/version.hpp"

int main() {
    std::cout << "[SecureCloud Client] Starting Desktop Client v" 
              << securecloud::common::get_version_string() << std::endl;
    return 0;
}
