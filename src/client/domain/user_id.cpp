#include "domain/user_id.hpp"

#include <iostream>
#include <stdexcept>
#include <utility>

namespace securecloud::client::domain {

UserId::UserId(std::string value) : value_(std::move(value)) {
    if (value_.empty()) {
        throw std::invalid_argument("UserId cannot be empty");
    }
}

std::ostream& operator<<(std::ostream& os, const UserId& id) {
    return os << id.value();
}

} // namespace securecloud::client::domain

