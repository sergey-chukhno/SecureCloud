#pragma once

#include "repository/conversation_repository_interface.hpp"

#include <shared_mutex>
#include <unordered_map>

namespace securecloud::messaging::repository {

/// Thread-safe in-memory implementation of IConversationRepository for hermetic testing and early service integration.
class InMemoryConversationRepository final : public IConversationRepository {
  public:
    InMemoryConversationRepository() = default;
    ~InMemoryConversationRepository() override = default;

    void save_conversation(const domain::ConversationEntity& conv) override;

    [[nodiscard]] std::optional<domain::ConversationEntity>
    find_conversation_by_id(const domain::ConversationId& id) override;

    [[nodiscard]] std::optional<domain::ConversationId>
    find_direct_conversation(const domain::DirectPair& pair) override;

    void save_direct_conversation(const domain::DirectPair& pair, const domain::ConversationId& id) override;

    void save_group_metadata(const domain::GroupMetadataEntity& meta) override;

    [[nodiscard]] std::optional<domain::GroupMetadataEntity>
    find_group_metadata(const domain::ConversationId& id) override;

    /// Clears all stored records (useful for test isolation).
    void clear();

  private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<domain::ConversationId, domain::ConversationEntity> conversations_;
    std::unordered_map<domain::DirectPair, domain::ConversationId> direct_pairs_;
    std::unordered_map<domain::ConversationId, domain::GroupMetadataEntity> group_metadata_;
};

} // namespace securecloud::messaging::repository
