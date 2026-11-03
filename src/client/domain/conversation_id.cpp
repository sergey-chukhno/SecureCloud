#include "domain/conversation_id.hpp"

#include <iostream>
#include <stdexcept>
#include <utility>

namespace securecloud::client::domain {

ConversationId::ConversationId(std::string value) : value_(std::move(value)) {
    if (value_.empty()) {
        throw std::invalid_argument("ConversationId cannot be empty");
    }
}

std::ostream& operator<<(std::ostream& os, const ConversationId& id) {
    return os << id.value();
}

} // namespace securecloud::client::domain

