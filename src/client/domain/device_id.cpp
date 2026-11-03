#include "domain/device_id.hpp"

#include <iostream>
#include <stdexcept>
#include <utility>

namespace securecloud::client::domain {

DeviceId::DeviceId(std::string value) : value_(std::move(value)) {
    if (value_.empty()) {
        throw std::invalid_argument("DeviceId cannot be empty");
    }
}

std::ostream& operator<<(std::ostream& os, const DeviceId& id) {
    return os << id.value();
}

} // namespace securecloud::client::domain

