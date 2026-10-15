#pragma once

#include "messaging/db/scylla_session_interface.hpp"
#include "messaging/repository/message_repository_interface.hpp"

#include <memory>
#include <mutex>

namespace securecloud::messaging::repository {

/// ScyllaDB persistence adapter for immutable conversation messages.
/// Conforms strictly to table:
/// securecloud_messaging.messages_by_conversation
/// - Partition Key: ((conversation_id, message_bucket))
/// - Clustering Key: message_sequence ASC, message_id ASC
class ScyllaMessageRepository : public IMessageRepository {
  public:
    explicit ScyllaMessageRepository(std::shared_ptr<db::IScyllaSession> session);

    void save_message(const domain::MessageEntity& msg) override;

    [[nodiscard]] std::optional<domain::MessageEntity> find_by_id(const domain::ConversationId& conversation_id,
                                                                  const domain::MessageBucket& message_bucket,
                                                                  const domain::MessageId& message_id) override;

    [[nodiscard]] std::vector<domain::MessageEntity>
    list_messages_by_sequence_range(const domain::ConversationId& conversation_id,
                                    const domain::MessageBucket& message_bucket, uint64_t from_sequence,
                                    uint64_t to_sequence, size_t limit) override;

    [[nodiscard]] uint64_t get_last_sequence(const domain::ConversationId& conversation_id,
                                             const domain::MessageBucket& message_bucket) override;

  private:
    void init_prepared_statements();

    std::shared_ptr<db::IScyllaSession> session_;
    mutable std::mutex mutex_;

    db::PreparedStatementId prep_save_message_;
    db::PreparedStatementId prep_find_by_id_;
    db::PreparedStatementId prep_list_range_;
    db::PreparedStatementId prep_get_last_seq_;
};

} // namespace securecloud::messaging::repository
