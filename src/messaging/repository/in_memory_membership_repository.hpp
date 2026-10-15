#pragma once

#include "repository/membership_repository_interface.hpp"

#include <algorithm>
#include <map>
#include <mutex>
#include <unordered_map>

namespace securecloud::messaging::repository {

/// Thread-safe in-memory implementation of IMembershipRepository for hermetic testing and early service integration.
class InMemoryMembershipRepository final : public IMembershipRepository {
  public:
    InMemoryMembershipRepository() = default;
    ~InMemoryMembershipRepository() override = default;

    void add_participant(const domain::ConversationParticipantEntity& participant) override;

    void update_participant(const domain::ConversationParticipantEntity& participant) override;

    [[nodiscard]] std::optional<domain::ConversationParticipantEntity>
    find_participant(const domain::ConversationId& conv_id, const domain::UserId& user_id) override;

    [[nodiscard]] std::vector<domain::ConversationParticipantEntity>
    list_participants(const domain::ConversationId& conv_id) override;

    [[nodiscard]] std::vector<domain::ConversationParticipantEntity>
    list_active_participants(const domain::ConversationId& conv_id) override;

    void touch_user_conversation(const domain::UserId& user_id, const domain::ConversationId& conv_id,
                                 domain::ConversationType type, domain::MembershipStatus status,
                                 std::chrono::system_clock::time_point activity_at) override;

    [[nodiscard]] UserConversationsPage list_user_conversations(const domain::UserId& user_id, int limit,
                                                                const std::optional<std::string>& page_token) override;

    /// Clears all stored records (useful for test isolation).
    void clear();

  private:
    struct ParticipantKey {
        domain::ConversationId conv_id;
        domain::UserId user_id;

        auto operator<=>(const ParticipantKey& other) const noexcept = default;
        bool operator==(const ParticipantKey& other) const noexcept = default;
    };

    struct ParticipantKeyHash {
        std::size_t operator()(const ParticipantKey& k) const noexcept {
            std::size_t h1 = std::hash<domain::ConversationId>{}(k.conv_id);
            std::size_t h2 = std::hash<domain::UserId>{}(k.user_id);
            return h1 ^ (h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2));
        }
    };

    mutable std::mutex mutex_;
    std::unordered_map<ParticipantKey, domain::ConversationParticipantEntity, ParticipantKeyHash> participants_;
    // user_id -> map<activity_at DESC, conversation_id> for deterministic pagination
    std::unordered_map<domain::UserId, std::vector<UserConversationSummary>> user_inboxes_;
};

} // namespace securecloud::messaging::repository
