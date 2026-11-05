#pragma once

#include "domain/conversation_id.hpp"
#include "domain/user_id.hpp"

#include <chrono>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::domain {

enum class ConversationType { Direct, Group };

[[nodiscard]] std::string_view to_string(ConversationType type) noexcept;

class Conversation {
  public:
    Conversation() = default;
    Conversation(ConversationId conversation_id, ConversationType type, std::string title = "",
                 std::vector<UserId> participants = {},
                 std::chrono::system_clock::time_point created_at = std::chrono::system_clock::now(),
                 std::chrono::system_clock::time_point last_activity_at = std::chrono::system_clock::now());

    [[nodiscard]] const ConversationId& conversation_id() const noexcept { return conversation_id_; }
    [[nodiscard]] ConversationType type() const noexcept { return type_; }
    [[nodiscard]] const std::string& title() const noexcept { return title_; }
    [[nodiscard]] const std::vector<UserId>& participants() const noexcept { return participants_; }
    [[nodiscard]] std::chrono::system_clock::time_point created_at() const noexcept { return created_at_; }
    [[nodiscard]] std::chrono::system_clock::time_point last_activity_at() const noexcept { return last_activity_at_; }

    void set_title(std::string title) { title_ = std::move(title); }
    void add_participant(UserId user_id);
    void remove_participant(const UserId& user_id);
    void set_last_activity_at(std::chrono::system_clock::time_point tp) noexcept { last_activity_at_ = tp; }

    bool operator==(const Conversation& other) const noexcept;
    bool operator!=(const Conversation& other) const noexcept { return !(*this == other); }

  private:
    ConversationId conversation_id_;
    ConversationType type_{ConversationType::Direct};
    std::string title_;
    std::vector<UserId> participants_;
    std::chrono::system_clock::time_point created_at_{std::chrono::system_clock::now()};
    std::chrono::system_clock::time_point last_activity_at_{std::chrono::system_clock::now()};
};

} // namespace securecloud::client::domain
