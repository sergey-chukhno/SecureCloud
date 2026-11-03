#include "domain/message_id.hpp"

#include <iostream>
#include <stdexcept>
#include <utility>

namespace securecloud::client::domain {

MessageId::MessageId(std::string value) : value_(std::move(value)) {
    if (value_.empty()) {
        throw std::invalid_argument("MessageId cannot be empty");
    }
}

std::ostream& operator<<(std::ostream& os, const MessageId& id) {
    return os << id.value();
}

} // namespace securecloud::client::domain

