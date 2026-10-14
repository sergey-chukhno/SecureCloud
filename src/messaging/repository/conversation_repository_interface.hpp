#pragma once

#include "domain/conversation_entity.hpp"
#include "domain/conversation_types.hpp"
#include "domain/group_metadata_entity.hpp"

#include <optional>

namespace securecloud::messaging::repository {

/// Abstract repository contract for Conversation metadata and direct pair lookups.
/// Conforms to ScyllaDB query patterns (ADR-005, 03-messaging-data-model.md):
/// - conversations_by_id
/// - direct_conversation_by_users
/// - group_metadata_by_conversation
class IConversationRepository {
  public:
    virtual ~IConversationRepository() = default;

    /// Persists or updates common conversation metadata (conversations_by_id).
    virtual void save_conversation(const domain::ConversationEntity& conv) = 0;

    /// Retrieves common conversation metadata by ConversationId.
    [[nodiscard]] virtual std::optional<domain::ConversationEntity>
    find_conversation_by_id(const domain::ConversationId& id) = 0;

    /// Finds an existing direct conversation ID for a canonical user pair (direct_conversation_by_users).
    [[nodiscard]] virtual std::optional<domain::ConversationId>
    find_direct_conversation(const domain::DirectPair& pair) = 0;

    /// Records the mapping between a canonical user pair and a direct conversation ID.
    virtual void save_direct_conversation(const domain::DirectPair& pair, const domain::ConversationId& id) = 0;

    /// Persists or updates group-specific metadata (group_metadata_by_conversation).
    virtual void save_group_metadata(const domain::GroupMetadataEntity& meta) = 0;

    /// Retrieves group-specific metadata by ConversationId.
    [[nodiscard]] virtual std::optional<domain::GroupMetadataEntity>
    find_group_metadata(const domain::ConversationId& id) = 0;
};

} // namespace securecloud::messaging::repository
