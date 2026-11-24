#pragma once

#include "application/client_error.hpp"
#include "domain/contact.hpp"
#include "domain/conversation.hpp"
#include "domain/conversation_id.hpp"
#include "domain/file_transfer.hpp"
#include "domain/message.hpp"
#include "domain/message_id.hpp"
#include "domain/offline_sync_models.hpp"
#include "domain/user_id.hpp"
#include "domain/user_profile.hpp"
#include "domain/user_settings.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::application::interfaces {

class ILocalStore {
  public:
    virtual ~ILocalStore() = default;

    virtual ClientResult<void> open(std::string_view path) = 0;
    virtual ClientResult<void> close() = 0;
    [[nodiscard]] virtual std::string database_path() const = 0;
    virtual ClientResult<std::size_t> destroy_and_shred() = 0;

    virtual ClientResult<void> save_conversation(const domain::Conversation& conversation) = 0;
    virtual ClientResult<domain::Conversation> get_conversation(const domain::ConversationId& id) = 0;
    virtual ClientResult<std::vector<domain::Conversation>> list_conversations() = 0;
    virtual ClientResult<void> delete_conversation(const domain::ConversationId& id) = 0;

    virtual ClientResult<void> save_message(const domain::Message& message) = 0;
    virtual ClientResult<std::vector<domain::Message>> get_messages(const domain::ConversationId& id,
                                                                    std::size_t limit) = 0;
    virtual ClientResult<domain::Message> get_message(const domain::ConversationId& conversation_id,
                                                      const domain::MessageId& message_id) = 0;
    virtual ClientResult<void> update_message(const domain::Message& message) = 0;

    virtual ClientResult<void> save_contact(const domain::Contact& contact) = 0;
    virtual ClientResult<domain::Contact> get_contact(const domain::UserId& user_id) = 0;
    virtual ClientResult<std::vector<domain::Contact>> list_contacts() = 0;
    virtual ClientResult<void> delete_contact(const domain::UserId& user_id) = 0;

    virtual ClientResult<void> save_file_transfer(const domain::FileTransferRecord& record) = 0;
    virtual ClientResult<domain::FileTransferRecord> get_file_transfer(std::string_view transfer_id) = 0;
    virtual ClientResult<std::vector<domain::FileTransferRecord>>
    list_file_transfers(const domain::ConversationId& conversation_id = {}) = 0;
    virtual ClientResult<void> delete_file_transfer(std::string_view transfer_id) = 0;

    virtual ClientResult<void> save_outbox_record(const domain::OfflineOutboxRecord& record) = 0;
    virtual ClientResult<domain::OfflineOutboxRecord> get_outbox_record(std::string_view outbox_id) = 0;
    virtual ClientResult<std::vector<domain::OfflineOutboxRecord>> list_outbox_records(std::size_t limit = 500) = 0;
    virtual ClientResult<void> delete_outbox_record(std::string_view outbox_id) = 0;

    virtual ClientResult<domain::SyncCursorRecord> save_sync_cursor(const domain::SyncCursorRecord& cursor) = 0;
    virtual ClientResult<domain::SyncCursorRecord> get_sync_cursor(const domain::DeviceId& device_id,
                                                                   const domain::ConversationId& conversation_id) = 0;
    virtual ClientResult<std::vector<domain::SyncCursorRecord>>
    list_sync_cursors(const domain::DeviceId& device_id) = 0;

    virtual ClientResult<void> save_user_profile(const domain::UserProfile& profile) = 0;
    virtual ClientResult<std::optional<domain::UserProfile>> get_user_profile(const domain::UserId& user_id) = 0;

    virtual ClientResult<void> save_user_settings(std::string_view profile_key,
                                                  const domain::UserSettings& settings) = 0;
    virtual ClientResult<std::optional<domain::UserSettings>> get_user_settings(std::string_view profile_key) = 0;

    virtual ClientResult<std::size_t> delete_expired_messages(int64_t now_ms) = 0;
};

} // namespace securecloud::client::application::interfaces
