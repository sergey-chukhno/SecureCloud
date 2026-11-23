#pragma once

#include "domain/conversation_id.hpp"
#include "domain/user_id.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::domain {

enum class ConversationType { Direct, Group };

enum class GroupStatus { Active, Closed };

enum class MembershipStatus { Active, Left, Removed };

enum class ParticipantRole { Member, Admin };

[[nodiscard]] std::string_view to_string(ConversationType type) noexcept;
[[nodiscard]] std::optional<ConversationType> conversation_type_from_string(std::string_view str) noexcept;

[[nodiscard]] std::string_view to_string(GroupStatus status) noexcept;
[[nodiscard]] std::optional<GroupStatus> group_status_from_string(std::string_view str) noexcept;

[[nodiscard]] std::string_view to_string(MembershipStatus status) noexcept;
[[nodiscard]] std::optional<MembershipStatus> membership_status_from_string(std::string_view str) noexcept;

[[nodiscard]] std::string_view to_string(ParticipantRole role) noexcept;
[[nodiscard]] std::optional<ParticipantRole> participant_role_from_string(std::string_view str) noexcept;

struct GroupParticipant {
    UserId user_id;
    ParticipantRole role{ParticipantRole::Member};
    MembershipStatus status{MembershipStatus::Active};
    std::chrono::system_clock::time_point joined_at{std::chrono::system_clock::now()};
    uint64_t membership_version{1};

    bool operator==(const GroupParticipant& other) const noexcept;
    bool operator!=(const GroupParticipant& other) const noexcept { return !(*this == other); }
};

class Conversation {
  public:
    Conversation() = default;
    Conversation(ConversationId conversation_id, ConversationType type, std::string title = "",
                 std::vector<UserId> participants = {},
                 std::chrono::system_clock::time_point created_at = std::chrono::system_clock::now(),
                 std::chrono::system_clock::time_point last_activity_at = std::chrono::system_clock::now(),
                 uint32_t unread_count = 0, bool is_muted = false);

    [[nodiscard]] const ConversationId& conversation_id() const noexcept { return conversation_id_; }
    [[nodiscard]] ConversationType type() const noexcept { return type_; }
    [[nodiscard]] const std::string& title() const noexcept { return title_; }
    [[nodiscard]] const std::vector<UserId>& participants() const noexcept { return participants_; }
    [[nodiscard]] const std::vector<GroupParticipant>& participant_records() const noexcept {
        return participant_records_;
    }
    [[nodiscard]] std::chrono::system_clock::time_point created_at() const noexcept { return created_at_; }
    [[nodiscard]] std::chrono::system_clock::time_point last_activity_at() const noexcept { return last_activity_at_; }
    [[nodiscard]] uint32_t unread_count() const noexcept { return unread_count_; }
    [[nodiscard]] bool is_muted() const noexcept { return is_muted_; }
    [[nodiscard]] GroupStatus group_status() const noexcept { return group_status_; }
    [[nodiscard]] uint64_t sender_key_epoch() const noexcept { return sender_key_epoch_; }

    void set_title(std::string title) { title_ = std::move(title); }
    void add_participant(UserId user_id);
    void add_participant(UserId user_id, ParticipantRole role);
    void remove_participant(const UserId& user_id);
    [[nodiscard]] bool has_participant(const UserId& user_id) const noexcept;
    [[nodiscard]] std::optional<GroupParticipant> find_participant(const UserId& user_id) const noexcept;
    [[nodiscard]] std::optional<ParticipantRole> role_of(const UserId& user_id) const noexcept;
    [[nodiscard]] bool is_admin(const UserId& user_id) const noexcept;
    bool set_participant_role(const UserId& user_id, ParticipantRole role);
    bool set_participant_status(const UserId& user_id, MembershipStatus status);
    void set_participant_records(std::vector<GroupParticipant> records);

    void set_last_activity_at(std::chrono::system_clock::time_point tp) noexcept { last_activity_at_ = tp; }
    void set_unread_count(uint32_t count) noexcept { unread_count_ = count; }
    void set_muted(bool muted) noexcept { is_muted_ = muted; }
    void set_group_status(GroupStatus status) noexcept { group_status_ = status; }
    void set_sender_key_epoch(uint64_t epoch) noexcept { sender_key_epoch_ = epoch; }
    uint64_t increment_sender_key_epoch() noexcept { return ++sender_key_epoch_; }

    [[nodiscard]] std::string to_json() const;
    static std::optional<Conversation> from_json(std::string_view json_str);

    bool operator==(const Conversation& other) const noexcept;
    bool operator!=(const Conversation& other) const noexcept { return !(*this == other); }

  private:
    void sync_active_participants();

    ConversationId conversation_id_;
    ConversationType type_{ConversationType::Direct};
    std::string title_;
    std::vector<UserId> participants_;
    std::vector<GroupParticipant> participant_records_;
    std::chrono::system_clock::time_point created_at_{std::chrono::system_clock::now()};
    std::chrono::system_clock::time_point last_activity_at_{std::chrono::system_clock::now()};
    uint32_t unread_count_{0};
    bool is_muted_{false};
    GroupStatus group_status_{GroupStatus::Active};
    uint64_t sender_key_epoch_{1};
};

} // namespace securecloud::client::domain
