#pragma once

#include <functional>
#include <iosfwd>
#include <string>
#include <string_view>

namespace securecloud::client::domain {

class ConversationId {
  public:
    ConversationId() = default;
    explicit ConversationId(std::string value);

    [[nodiscard]] const std::string& value() const noexcept { return value_; }
    [[nodiscard]] std::string_view str() const noexcept { return value_; }
    [[nodiscard]] bool empty() const noexcept { return value_.empty(); }

    bool operator==(const ConversationId& other) const noexcept { return value_ == other.value_; }
    bool operator!=(const ConversationId& other) const noexcept { return value_ != other.value_; }
    bool operator<(const ConversationId& other) const noexcept { return value_ < other.value_; }

  private:
    std::string value_;
};

std::ostream& operator<<(std::ostream& os, const ConversationId& id);

} // namespace securecloud::client::domain

template <> struct std::hash<securecloud::client::domain::ConversationId> {
    std::size_t operator()(const securecloud::client::domain::ConversationId& id) const noexcept {
        return std::hash<std::string>{}(id.value());
    }
};
