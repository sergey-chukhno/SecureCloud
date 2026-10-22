#pragma once

#include "messaging/db/scylla_session_interface.hpp"
#include "messaging/repository/conversation_repository_interface.hpp"

#include <memory>
#include <mutex>

namespace securecloud::messaging::repository {

/// ScyllaDB persistence adapter for Conversation metadata and direct user pair mappings.
/// Conforms strictly to tables:
/// - securecloud_messaging.conversations_by_id
/// - securecloud_messaging.direct_conversation_by_users
/// - securecloud_messaging.group_metadata_by_conversation
class ScyllaConversationRepository : public IConversationRepository {
  public:
    explicit ScyllaConversationRepository(std::shared_ptr<db::IScyllaSession> session);

    void save_conversation(const domain::ConversationEntity& conv) override;

    [[nodiscard]] std::optional<domain::ConversationEntity>
    find_conversation_by_id(const domain::ConversationId& id) override;

    [[nodiscard]] std::optional<domain::ConversationId>
    find_direct_conversation(const domain::DirectPair& pair) override;

    void save_direct_conversation(const domain::DirectPair& pair, const domain::ConversationId& id) override;

    void save_group_metadata(const domain::GroupMetadataEntity& meta) override;

    [[nodiscard]] std::optional<domain::GroupMetadataEntity>
    find_group_metadata(const domain::ConversationId& id) override;

  private:
    void init_prepared_statements();

    std::shared_ptr<db::IScyllaSession> session_;
    mutable std::mutex mutex_;

    db::PreparedStatementId prep_save_conv_;
    db::PreparedStatementId prep_find_conv_;
    db::PreparedStatementId prep_save_direct_;
    db::PreparedStatementId prep_find_direct_;
    db::PreparedStatementId prep_save_group_meta_;
    db::PreparedStatementId prep_find_group_meta_;
};

} // namespace securecloud::messaging::repository
