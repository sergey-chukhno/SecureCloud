#pragma once

#include "application/interfaces/i_crypto_provider.hpp"
#include "application/interfaces/i_local_store.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "infrastructure/adapters/file_shredder.hpp"

#include <mutex>
#include <string>

struct sqlite3;

namespace securecloud::client::infrastructure::adapters {

class SqlCipherLocalStore final : public application::interfaces::ILocalStore {
  public:
    static constexpr std::string_view kMasterKeyId = "local_store.sqlcipher.master_key";

    SqlCipherLocalStore(application::interfaces::ISecureStorage& secure_storage,
                        application::interfaces::ICryptoProvider& crypto_provider);
    ~SqlCipherLocalStore() override;

    SqlCipherLocalStore(const SqlCipherLocalStore&) = delete;
    SqlCipherLocalStore& operator=(const SqlCipherLocalStore&) = delete;
    SqlCipherLocalStore(SqlCipherLocalStore&&) = delete;
    SqlCipherLocalStore& operator=(SqlCipherLocalStore&&) = delete;

    application::ClientResult<void> open(std::string_view path) override;
    application::ClientResult<void> close() override;
    [[nodiscard]] std::string database_path() const override;
    application::ClientResult<std::size_t> destroy_and_shred() override;
    application::ClientResult<std::size_t> destroy_and_shred(const ShredOptions& options);

    application::ClientResult<void> save_conversation(const domain::Conversation& conversation) override;
    application::ClientResult<domain::Conversation> get_conversation(const domain::ConversationId& id) override;
    application::ClientResult<std::vector<domain::Conversation>> list_conversations() override;
    application::ClientResult<void> delete_conversation(const domain::ConversationId& id) override;

    application::ClientResult<void> save_message(const domain::Message& message) override;
    application::ClientResult<std::vector<domain::Message>> get_messages(const domain::ConversationId& id,
                                                                         std::size_t limit) override;
    application::ClientResult<domain::Message> get_message(const domain::ConversationId& conversation_id,
                                                           const domain::MessageId& message_id) override;
    application::ClientResult<void> update_message(const domain::Message& message) override;
    application::ClientResult<void> delete_message(const domain::ConversationId& conversation_id,
                                                   const domain::MessageId& message_id) override;

    application::ClientResult<void> save_contact(const domain::Contact& contact) override;
    application::ClientResult<domain::Contact> get_contact(const domain::UserId& user_id) override;
    application::ClientResult<std::vector<domain::Contact>> list_contacts() override;
    application::ClientResult<void> delete_contact(const domain::UserId& user_id) override;

    application::ClientResult<void> save_file_transfer(const domain::FileTransferRecord& record) override;
    application::ClientResult<domain::FileTransferRecord> get_file_transfer(std::string_view transfer_id) override;
    application::ClientResult<std::vector<domain::FileTransferRecord>>
    list_file_transfers(const domain::ConversationId& conversation_id = {}) override;
    application::ClientResult<void> delete_file_transfer(std::string_view transfer_id) override;

    application::ClientResult<void> save_outbox_record(const domain::OfflineOutboxRecord& record) override;
    application::ClientResult<domain::OfflineOutboxRecord> get_outbox_record(std::string_view outbox_id) override;
    application::ClientResult<std::vector<domain::OfflineOutboxRecord>>
    list_outbox_records(std::size_t limit = 500) override;
    application::ClientResult<void> delete_outbox_record(std::string_view outbox_id) override;

    application::ClientResult<domain::SyncCursorRecord>
    save_sync_cursor(const domain::SyncCursorRecord& cursor) override;
    application::ClientResult<domain::SyncCursorRecord>
    get_sync_cursor(const domain::DeviceId& device_id, const domain::ConversationId& conversation_id) override;
    application::ClientResult<std::vector<domain::SyncCursorRecord>>
    list_sync_cursors(const domain::DeviceId& device_id) override;

    application::ClientResult<void> save_user_profile(const domain::UserProfile& profile) override;
    application::ClientResult<std::optional<domain::UserProfile>>
    get_user_profile(const domain::UserId& user_id) override;

    application::ClientResult<void> save_user_settings(std::string_view profile_key,
                                                       const domain::UserSettings& settings) override;
    application::ClientResult<std::optional<domain::UserSettings>>
    get_user_settings(std::string_view profile_key) override;

    application::ClientResult<std::size_t> delete_expired_messages(int64_t now_ms) override;

    application::ClientResult<void> append_audit_event(const domain::LocalAuditEvent& event) override;
    application::ClientResult<std::vector<domain::LocalAuditEvent>> list_audit_events(std::size_t limit = 100,
                                                                                      std::size_t offset = 0) override;
    application::ClientResult<std::optional<domain::LocalAuditEvent>> get_latest_audit_event() override;
    application::ClientResult<std::size_t> count_audit_events() override;

    [[nodiscard]] bool is_open() const noexcept;

  private:
    application::ClientResult<void> exec_sql_locked(const char* sql);
    application::ClientResult<void> exec_delete_for_conversation_locked(const char* sql,
                                                                        const domain::ConversationId& id);
    application::ClientResult<void> initialize_schema_locked();
    application::ClientResult<void> migrate_messages_expires_at_locked();
    void close_locked() noexcept;

    application::interfaces::ISecureStorage& secure_storage_;
    application::interfaces::ICryptoProvider& crypto_provider_;
    mutable std::mutex mutex_;
    sqlite3* db_{nullptr};
    std::string db_path_;
    std::string last_db_path_;
};

} // namespace securecloud::client::infrastructure::adapters
