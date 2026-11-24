#include "infrastructure/adapters/sqlcipher_local_store.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <string>
#include <vector>

#if __has_include(<sqlcipher/sqlite3.h>)
#include <sqlcipher/sqlite3.h>
#else
#include <sqlite3.h>
#endif

namespace securecloud::client::infrastructure::adapters {

namespace {

class StmtGuard {
  public:
    explicit StmtGuard(sqlite3_stmt* stmt = nullptr) noexcept : stmt_(stmt) {}
    ~StmtGuard() {
        if (stmt_ != nullptr) {
            sqlite3_finalize(stmt_);
        }
    }

    StmtGuard(const StmtGuard&) = delete;
    StmtGuard& operator=(const StmtGuard&) = delete;

    [[nodiscard]] sqlite3_stmt* get() const noexcept { return stmt_; }
    sqlite3_stmt** out() noexcept { return &stmt_; }

  private:
    sqlite3_stmt* stmt_{nullptr};
};

class SecretCleanseGuard {
  public:
    explicit SecretCleanseGuard(std::string& s) noexcept : target_(s) {}
    ~SecretCleanseGuard() {
        if (!target_.empty()) {
            OPENSSL_cleanse(target_.data(), target_.size());
            target_.clear();
        }
    }

  private:
    std::string& target_;
};

[[nodiscard]] bool is_valid_hex_key(std::string_view key_hex) noexcept {
    if (key_hex.size() != 64) {
        return false;
    }
    for (char raw_ch : key_hex) {
        const auto ch = static_cast<unsigned char>(raw_ch);
        const bool is_hex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
        if (!is_hex) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::string generate_hex_key_256() {
    static constexpr char kHexDigits[] = "0123456789abcdef";
    std::array<uint8_t, 32> raw{};
    if (RAND_bytes(raw.data(), static_cast<int>(raw.size())) != 1) {
        return {};
    }
    std::string hex;
    hex.reserve(64);
    for (uint8_t b : raw) {
        hex.push_back(kHexDigits[(b >> 4) & 0x0F]);
        hex.push_back(kHexDigits[b & 0x0F]);
    }
    OPENSSL_cleanse(raw.data(), raw.size());
    return hex;
}

[[nodiscard]] std::string column_text_string(sqlite3_stmt* stmt, int col) {
    const unsigned char* ptr = sqlite3_column_text(stmt, col);
    if (ptr == nullptr) {
        return {};
    }
    const int bytes = sqlite3_column_bytes(stmt, col);
    if (bytes <= 0) {
        return {};
    }
    return std::string(reinterpret_cast<const char*>(ptr), static_cast<std::size_t>(bytes));
}

[[nodiscard]] int64_t current_unix_ms() noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

SqlCipherLocalStore::SqlCipherLocalStore(application::interfaces::ISecureStorage& secure_storage,
                                         application::interfaces::ICryptoProvider& crypto_provider)
    : secure_storage_(secure_storage), crypto_provider_(crypto_provider) {}

SqlCipherLocalStore::~SqlCipherLocalStore() {
    std::lock_guard<std::mutex> lock(mutex_);
    close_locked();
}

bool SqlCipherLocalStore::is_open() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return db_ != nullptr;
}

void SqlCipherLocalStore::close_locked() noexcept {
    if (db_ != nullptr) {
        sqlite3_close_v2(db_);
        db_ = nullptr;
    }
    db_path_.clear();
}

application::ClientResult<void> SqlCipherLocalStore::exec_sql_locked(const char* sql) {
    char* err_msg = nullptr;
    const int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string msg = err_msg != nullptr ? std::string(err_msg) : sqlite3_errmsg(db_);
        if (err_msg != nullptr) {
            sqlite3_free(err_msg);
        }
        return application::ClientResult<void>::error(application::ClientError::storage(std::move(msg)));
    }
    return application::ClientResult<void>::ok();
}

application::ClientResult<void> SqlCipherLocalStore::initialize_schema_locked() {
    static constexpr const char* kSchemaSql = R"sql(
        PRAGMA foreign_keys = ON;
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;

        CREATE TABLE IF NOT EXISTS conversations (
            conversation_id TEXT PRIMARY KEY,
            last_activity_at_ms INTEGER NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_conversations_last_activity
            ON conversations(last_activity_at_ms DESC);

        CREATE TABLE IF NOT EXISTS messages (
            message_id TEXT PRIMARY KEY,
            conversation_id TEXT NOT NULL,
            sent_at_ms INTEGER NOT NULL,
            payload_json TEXT NOT NULL,
            expires_at_ms INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_messages_conv_time
            ON messages(conversation_id, sent_at_ms ASC);

        CREATE TABLE IF NOT EXISTS user_profile (
            user_id TEXT PRIMARY KEY,
            updated_at_ms INTEGER NOT NULL,
            payload_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS user_settings (
            profile_key TEXT PRIMARY KEY,
            updated_at_ms INTEGER NOT NULL,
            payload_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS contacts (
            user_id TEXT PRIMARY KEY,
            payload_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS file_transfers (
            transfer_id TEXT PRIMARY KEY,
            conversation_id TEXT NOT NULL,
            updated_at_ms INTEGER NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_file_transfers_updated
            ON file_transfers(updated_at_ms DESC);
        CREATE INDEX IF NOT EXISTS idx_file_transfers_conv_updated
            ON file_transfers(conversation_id, updated_at_ms DESC);

        CREATE TABLE IF NOT EXISTS offline_outbox (
            outbox_id TEXT PRIMARY KEY,
            operation_type TEXT NOT NULL,
            conversation_id TEXT NOT NULL,
            priority INTEGER NOT NULL DEFAULT 0,
            created_at_ms INTEGER NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_offline_outbox_order
            ON offline_outbox(priority DESC, created_at_ms ASC, outbox_id ASC);

        CREATE TABLE IF NOT EXISTS sync_cursors (
            device_id TEXT NOT NULL,
            conversation_id TEXT NOT NULL,
            last_delivered_sequence INTEGER NOT NULL DEFAULT 0,
            updated_at_ms INTEGER NOT NULL,
            payload_json TEXT NOT NULL,
            PRIMARY KEY (device_id, conversation_id)
        );
    )sql";
    auto schema_res = exec_sql_locked(kSchemaSql);
    if (schema_res.is_error()) {
        return schema_res;
    }
    return migrate_messages_expires_at_locked();
}

application::ClientResult<void> SqlCipherLocalStore::migrate_messages_expires_at_locked() {
    bool has_expires_at = false;
    {
        StmtGuard stmt;
        if (sqlite3_prepare_v2(db_, "PRAGMA table_info(messages);", -1, stmt.out(), nullptr) != SQLITE_OK) {
            return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
        }
        while (true) {
            const int rc = sqlite3_step(stmt.get());
            if (rc == SQLITE_ROW) {
                if (column_text_string(stmt.get(), 1) == "expires_at_ms") {
                    has_expires_at = true;
                    break;
                }
            } else if (rc == SQLITE_DONE) {
                break;
            } else {
                return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
            }
        }
    }

    if (!has_expires_at) {
        auto alter_res = exec_sql_locked("ALTER TABLE messages ADD COLUMN expires_at_ms INTEGER NOT NULL DEFAULT 0;");
        if (alter_res.is_error()) {
            return alter_res;
        }
    }

    return exec_sql_locked("CREATE INDEX IF NOT EXISTS idx_messages_expires_at "
                           "ON messages(expires_at_ms) WHERE expires_at_ms > 0;");
}

application::ClientResult<void> SqlCipherLocalStore::open(std::string_view path) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (path.empty()) {
        return application::ClientResult<void>::error(
            application::ClientError::storage("SqlCipherLocalStore path cannot be empty"));
    }

    // Keep reference to crypto_provider_ active (used for production provider validation / future key wrapping)
    (void)crypto_provider_;

    close_locked();

    std::error_code ec;
    const std::filesystem::path fs_path(path);
    const bool db_exists = std::filesystem::exists(fs_path, ec);
    if (ec) {
        return application::ClientResult<void>::error(
            application::ClientError::storage("Failed to stat database path: " + ec.message()));
    }

    if (fs_path.has_parent_path()) {
        std::filesystem::create_directories(fs_path.parent_path(), ec);
        if (ec) {
            return application::ClientResult<void>::error(
                application::ClientError::storage("Failed to create database directory: " + ec.message()));
        }
    }

    std::string key_hex;
    SecretCleanseGuard key_guard(key_hex);

    auto has_key_res = secure_storage_.has_secret(kMasterKeyId);
    if (has_key_res.is_error()) {
        return application::ClientResult<void>::error(has_key_res.error());
    }

    if (has_key_res.value()) {
        auto key_res = secure_storage_.get_secret(kMasterKeyId);
        if (key_res.is_error()) {
            return application::ClientResult<void>::error(key_res.error());
        }
        key_hex = key_res.value().expose_unredacted_secret();
        if (!is_valid_hex_key(key_hex)) {
            return application::ClientResult<void>::error(
                application::ClientError::crypto("Invalid SQLCipher master key format in ISecureStorage"));
        }
    } else {
        if (db_exists && std::filesystem::file_size(fs_path, ec) > 0) {
            return application::ClientResult<void>::error(application::ClientError::crypto(
                "Missing SQLCipher master key in ISecureStorage for existing encrypted database"));
        }
        key_hex = generate_hex_key_256();
        if (!is_valid_hex_key(key_hex)) {
            return application::ClientResult<void>::error(
                application::ClientError::crypto("Failed to generate CSPRNG SQLCipher master key"));
        }
        auto store_res =
            secure_storage_.store_secret(kMasterKeyId, securecloud::common::configuration::SecretString(key_hex));
        if (store_res.is_error()) {
            return application::ClientResult<void>::error(store_res.error());
        }
    }

    const std::string path_str(path);
    sqlite3* raw_db = nullptr;
    const int open_rc = sqlite3_open_v2(path_str.c_str(), &raw_db,
                                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
    if (open_rc != SQLITE_OK || raw_db == nullptr) {
        std::string err = raw_db != nullptr ? sqlite3_errmsg(raw_db) : "sqlite3_open_v2 failed";
        if (raw_db != nullptr) {
            sqlite3_close_v2(raw_db);
        }
        return application::ClientResult<void>::error(application::ClientError::storage(std::move(err)));
    }

    db_ = raw_db;
    db_path_ = path_str;
    last_db_path_ = path_str;

    std::string pragma_key = "PRAGMA key = \"x'" + key_hex + "'\";";
    SecretCleanseGuard pragma_guard(pragma_key);

    auto key_exec_res = exec_sql_locked(pragma_key.c_str());
    if (key_exec_res.is_error()) {
        close_locked();
        return key_exec_res;
    }

    auto mem_sec_res = exec_sql_locked("PRAGMA cipher_memory_security = ON;");
    if (mem_sec_res.is_error()) {
        close_locked();
        return mem_sec_res;
    }

    // Force SQLCipher to read page 1 and verify key + HMAC before proceeding (fail closed on wrong key / corruption)
    auto verify_res = exec_sql_locked("SELECT count(*) FROM sqlite_master;");
    if (verify_res.is_error()) {
        close_locked();
        return application::ClientResult<void>::error(
            application::ClientError::crypto("SQLCipher key verification failed (wrong key or corrupt database)"));
    }

    auto schema_res = initialize_schema_locked();
    if (schema_res.is_error()) {
        close_locked();
        return schema_res;
    }

    return application::ClientResult<void>::ok();
}

application::ClientResult<void> SqlCipherLocalStore::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    close_locked();
    return application::ClientResult<void>::ok();
}

std::string SqlCipherLocalStore::database_path() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return db_path_;
}

application::ClientResult<std::size_t> SqlCipherLocalStore::destroy_and_shred() {
    return destroy_and_shred(ShredOptions{});
}

application::ClientResult<std::size_t> SqlCipherLocalStore::destroy_and_shred(const ShredOptions& options) {
    std::string target_path;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        target_path = !db_path_.empty() ? db_path_ : last_db_path_;
        close_locked();
        last_db_path_.clear();
    }

    std::size_t files_shredded = 0U;
    std::vector<std::string> errors;

    if (!target_path.empty()) {
        const std::vector<std::filesystem::path> artifacts{
            std::filesystem::path(target_path),
            std::filesystem::path(target_path + "-wal"),
            std::filesystem::path(target_path + "-shm"),
            std::filesystem::path(target_path + "-journal"),
        };
        const auto shred_res = FileShredder::shred_files(artifacts, options);
        if (shred_res.is_error()) {
            errors.push_back(shred_res.error().user_message());
        } else {
            files_shredded = shred_res.value().files_shredded;
            if (!shred_res.value().failed_paths.empty()) {
                for (const auto& err : shred_res.value().failed_paths) {
                    errors.push_back(err);
                }
            }
        }
    }

    (void)secure_storage_.delete_secret(kMasterKeyId);

    if (!errors.empty()) {
        return application::ClientResult<std::size_t>::error(application::ClientError::storage(errors.front()));
    }
    return application::ClientResult<std::size_t>::ok(files_shredded);
}

application::ClientResult<void> SqlCipherLocalStore::save_conversation(const domain::Conversation& conversation) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<void>::error(application::ClientError::storage("Storage is closed"));
    }

    static constexpr const char* kSql = R"sql(
        INSERT INTO conversations (conversation_id, last_activity_at_ms, payload_json)
        VALUES (?1, ?2, ?3)
        ON CONFLICT(conversation_id) DO UPDATE SET
            last_activity_at_ms = excluded.last_activity_at_ms,
            payload_json = excluded.payload_json;
    )sql";

    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    const std::string& cid = conversation.conversation_id().value();
    const auto last_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(conversation.last_activity_at().time_since_epoch())
            .count();
    const std::string json = conversation.to_json();

    sqlite3_bind_text(stmt.get(), 1, cid.c_str(), static_cast<int>(cid.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 2, static_cast<sqlite3_int64>(last_ms));
    sqlite3_bind_text(stmt.get(), 3, json.c_str(), static_cast<int>(json.size()), SQLITE_TRANSIENT);

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }
    return application::ClientResult<void>::ok();
}

application::ClientResult<domain::Conversation>
SqlCipherLocalStore::get_conversation(const domain::ConversationId& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<domain::Conversation>::error(
            application::ClientError::storage("Storage is closed"));
    }

    static constexpr const char* kSql = "SELECT payload_json FROM conversations WHERE conversation_id = ?1;";
    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<domain::Conversation>::error(
            application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    sqlite3_bind_text(stmt.get(), 1, id.value().c_str(), static_cast<int>(id.value().size()), SQLITE_TRANSIENT);
    const int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        const std::string json = column_text_string(stmt.get(), 0);
        auto conv_opt = domain::Conversation::from_json(json);
        if (!conv_opt.has_value()) {
            return application::ClientResult<domain::Conversation>::error(
                application::ClientError::storage("Corrupt conversation JSON in SQLCipher store"));
        }
        return application::ClientResult<domain::Conversation>::ok(std::move(*conv_opt));
    }
    if (rc == SQLITE_DONE) {
        return application::ClientResult<domain::Conversation>::error(
            application::ClientError::storage("Conversation not found"));
    }
    return application::ClientResult<domain::Conversation>::error(
        application::ClientError::storage(sqlite3_errmsg(db_)));
}

application::ClientResult<std::vector<domain::Conversation>> SqlCipherLocalStore::list_conversations() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<std::vector<domain::Conversation>>::error(
            application::ClientError::storage("Storage is closed"));
    }

    static constexpr const char* kSql =
        "SELECT payload_json FROM conversations ORDER BY last_activity_at_ms DESC, rowid DESC;";
    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<std::vector<domain::Conversation>>::error(
            application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    std::vector<domain::Conversation> result;
    while (true) {
        const int rc = sqlite3_step(stmt.get());
        if (rc == SQLITE_ROW) {
            auto conv_opt = domain::Conversation::from_json(column_text_string(stmt.get(), 0));
            if (!conv_opt.has_value()) {
                return application::ClientResult<std::vector<domain::Conversation>>::error(
                    application::ClientError::storage("Corrupt conversation JSON in SQLCipher store"));
            }
            result.push_back(std::move(*conv_opt));
        } else if (rc == SQLITE_DONE) {
            break;
        } else {
            return application::ClientResult<std::vector<domain::Conversation>>::error(
                application::ClientError::storage(sqlite3_errmsg(db_)));
        }
    }
    return application::ClientResult<std::vector<domain::Conversation>>::ok(std::move(result));
}

application::ClientResult<void>
SqlCipherLocalStore::exec_delete_for_conversation_locked(const char* sql, const domain::ConversationId& id) {
    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }
    sqlite3_bind_text(stmt.get(), 1, id.value().c_str(), static_cast<int>(id.value().size()), SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }
    return application::ClientResult<void>::ok();
}

application::ClientResult<void> SqlCipherLocalStore::delete_conversation(const domain::ConversationId& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<void>::error(application::ClientError::storage("Storage is closed"));
    }

    auto begin_res = exec_sql_locked("BEGIN IMMEDIATE;");
    if (begin_res.is_error()) {
        return begin_res;
    }

    static constexpr const char* kCascadeTables[] = {
        "DELETE FROM messages WHERE conversation_id = ?1;",
        "DELETE FROM file_transfers WHERE conversation_id = ?1;",
        "DELETE FROM offline_outbox WHERE conversation_id = ?1;",
        "DELETE FROM sync_cursors WHERE conversation_id = ?1;",
    };
    for (const char* sql : kCascadeTables) {
        auto del_res = exec_delete_for_conversation_locked(sql, id);
        if (del_res.is_error()) {
            (void)exec_sql_locked("ROLLBACK;");
            return del_res;
        }
    }

    {
        StmtGuard del_conv;
        if (sqlite3_prepare_v2(db_, "DELETE FROM conversations WHERE conversation_id = ?1;", -1, del_conv.out(),
                               nullptr) != SQLITE_OK) {
            (void)exec_sql_locked("ROLLBACK;");
            return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
        }
        sqlite3_bind_text(del_conv.get(), 1, id.value().c_str(), static_cast<int>(id.value().size()), SQLITE_TRANSIENT);
        if (sqlite3_step(del_conv.get()) != SQLITE_DONE) {
            (void)exec_sql_locked("ROLLBACK;");
            return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
        }
        if (sqlite3_changes(db_) == 0) {
            (void)exec_sql_locked("ROLLBACK;");
            return application::ClientResult<void>::error(application::ClientError::storage("Conversation not found"));
        }
    }

    return exec_sql_locked("COMMIT;");
}

application::ClientResult<void> SqlCipherLocalStore::save_message(const domain::Message& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<void>::error(application::ClientError::storage("Storage is closed"));
    }

    static constexpr const char* kSql = R"sql(
        INSERT INTO messages (message_id, conversation_id, sent_at_ms, payload_json, expires_at_ms)
        VALUES (?1, ?2, ?3, ?4, ?5)
        ON CONFLICT(message_id) DO UPDATE SET
            conversation_id = excluded.conversation_id,
            sent_at_ms = excluded.sent_at_ms,
            payload_json = excluded.payload_json,
            expires_at_ms = excluded.expires_at_ms;
    )sql";

    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    const std::string& mid = message.message_id().value();
    const std::string& cid = message.conversation_id().value();
    const auto sent_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(message.sent_at().time_since_epoch()).count();
    const std::string json = message.to_json();

    sqlite3_bind_text(stmt.get(), 1, mid.c_str(), static_cast<int>(mid.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, cid.c_str(), static_cast<int>(cid.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 3, static_cast<sqlite3_int64>(sent_ms));
    sqlite3_bind_text(stmt.get(), 4, json.c_str(), static_cast<int>(json.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 5, static_cast<sqlite3_int64>(message.expires_at_ms()));

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }
    return application::ClientResult<void>::ok();
}

application::ClientResult<std::vector<domain::Message>>
SqlCipherLocalStore::get_messages(const domain::ConversationId& id, std::size_t limit) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<std::vector<domain::Message>>::error(
            application::ClientError::storage("Storage is closed"));
    }

    const char* sql = (limit > 0) ? "SELECT payload_json FROM messages WHERE conversation_id = ?1 "
                                    "AND (expires_at_ms = 0 OR expires_at_ms > ?2) "
                                    "ORDER BY sent_at_ms ASC, rowid ASC LIMIT ?3;"
                                  : "SELECT payload_json FROM messages WHERE conversation_id = ?1 "
                                    "AND (expires_at_ms = 0 OR expires_at_ms > ?2) "
                                    "ORDER BY sent_at_ms ASC, rowid ASC;";

    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<std::vector<domain::Message>>::error(
            application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    const int64_t now_ms = current_unix_ms();
    sqlite3_bind_text(stmt.get(), 1, id.value().c_str(), static_cast<int>(id.value().size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 2, static_cast<sqlite3_int64>(now_ms));
    if (limit > 0) {
        sqlite3_bind_int64(stmt.get(), 3, static_cast<sqlite3_int64>(limit));
    }

    std::vector<domain::Message> result;
    while (true) {
        const int rc = sqlite3_step(stmt.get());
        if (rc == SQLITE_ROW) {
            auto msg_opt = domain::Message::from_json(column_text_string(stmt.get(), 0));
            if (!msg_opt.has_value()) {
                return application::ClientResult<std::vector<domain::Message>>::error(
                    application::ClientError::storage("Corrupt message JSON in SQLCipher store"));
            }
            if (!msg_opt->is_expired(now_ms)) {
                result.push_back(std::move(*msg_opt));
            }
        } else if (rc == SQLITE_DONE) {
            break;
        } else {
            return application::ClientResult<std::vector<domain::Message>>::error(
                application::ClientError::storage(sqlite3_errmsg(db_)));
        }
    }
    return application::ClientResult<std::vector<domain::Message>>::ok(std::move(result));
}

application::ClientResult<domain::Message>
SqlCipherLocalStore::get_message(const domain::ConversationId& conversation_id, const domain::MessageId& message_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<domain::Message>::error(
            application::ClientError::storage("Storage is closed"));
    }

    static constexpr const char* kSql =
        "SELECT payload_json FROM messages WHERE conversation_id = ?1 AND message_id = ?2 "
        "AND (expires_at_ms = 0 OR expires_at_ms > ?3);";
    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<domain::Message>::error(
            application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    const int64_t now_ms = current_unix_ms();
    sqlite3_bind_text(stmt.get(), 1, conversation_id.value().c_str(), static_cast<int>(conversation_id.value().size()),
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, message_id.value().c_str(), static_cast<int>(message_id.value().size()),
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 3, static_cast<sqlite3_int64>(now_ms));

    const int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        auto msg_opt = domain::Message::from_json(column_text_string(stmt.get(), 0));
        if (!msg_opt.has_value()) {
            return application::ClientResult<domain::Message>::error(
                application::ClientError::storage("Corrupt message JSON in SQLCipher store"));
        }
        if (msg_opt->is_expired(now_ms)) {
            return application::ClientResult<domain::Message>::error(
                application::ClientError::storage("Message not found"));
        }
        return application::ClientResult<domain::Message>::ok(std::move(*msg_opt));
    }
    if (rc == SQLITE_DONE) {
        return application::ClientResult<domain::Message>::error(
            application::ClientError::storage("Message not found"));
    }
    return application::ClientResult<domain::Message>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
}

application::ClientResult<void> SqlCipherLocalStore::update_message(const domain::Message& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<void>::error(application::ClientError::storage("Storage is closed"));
    }

    static constexpr const char* kSql = R"sql(
        UPDATE messages SET sent_at_ms = ?1, payload_json = ?2, expires_at_ms = ?3
        WHERE conversation_id = ?4 AND message_id = ?5;
    )sql";
    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    const auto sent_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(message.sent_at().time_since_epoch()).count();
    const std::string json = message.to_json();
    const std::string& cid = message.conversation_id().value();
    const std::string& mid = message.message_id().value();

    sqlite3_bind_int64(stmt.get(), 1, static_cast<sqlite3_int64>(sent_ms));
    sqlite3_bind_text(stmt.get(), 2, json.c_str(), static_cast<int>(json.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 3, static_cast<sqlite3_int64>(message.expires_at_ms()));
    sqlite3_bind_text(stmt.get(), 4, cid.c_str(), static_cast<int>(cid.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 5, mid.c_str(), static_cast<int>(mid.size()), SQLITE_TRANSIENT);

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }
    if (sqlite3_changes(db_) == 0) {
        return application::ClientResult<void>::error(application::ClientError::storage("Message not found"));
    }
    return application::ClientResult<void>::ok();
}

application::ClientResult<void> SqlCipherLocalStore::save_contact(const domain::Contact& contact) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<void>::error(application::ClientError::storage("Storage is closed"));
    }

    static constexpr const char* kSql = R"sql(
        INSERT INTO contacts (user_id, payload_json)
        VALUES (?1, ?2)
        ON CONFLICT(user_id) DO UPDATE SET
            payload_json = excluded.payload_json;
    )sql";

    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    const std::string& uid = contact.user_id().value();
    const std::string json = contact.to_json();
    sqlite3_bind_text(stmt.get(), 1, uid.c_str(), static_cast<int>(uid.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, json.c_str(), static_cast<int>(json.size()), SQLITE_TRANSIENT);

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }
    return application::ClientResult<void>::ok();
}

application::ClientResult<domain::Contact> SqlCipherLocalStore::get_contact(const domain::UserId& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<domain::Contact>::error(
            application::ClientError::storage("Storage is closed"));
    }

    static constexpr const char* kSql = "SELECT payload_json FROM contacts WHERE user_id = ?1;";
    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<domain::Contact>::error(
            application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    sqlite3_bind_text(stmt.get(), 1, user_id.value().c_str(), static_cast<int>(user_id.value().size()),
                      SQLITE_TRANSIENT);
    const int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        auto contact_opt = domain::Contact::from_json(column_text_string(stmt.get(), 0));
        if (!contact_opt.has_value()) {
            return application::ClientResult<domain::Contact>::error(
                application::ClientError::storage("Corrupt contact JSON in SQLCipher store"));
        }
        return application::ClientResult<domain::Contact>::ok(std::move(*contact_opt));
    }
    if (rc == SQLITE_DONE) {
        return application::ClientResult<domain::Contact>::error(
            application::ClientError::storage("Contact not found"));
    }
    return application::ClientResult<domain::Contact>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
}

application::ClientResult<std::vector<domain::Contact>> SqlCipherLocalStore::list_contacts() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<std::vector<domain::Contact>>::error(
            application::ClientError::storage("Storage is closed"));
    }

    static constexpr const char* kSql = "SELECT payload_json FROM contacts ORDER BY user_id ASC;";
    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<std::vector<domain::Contact>>::error(
            application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    std::vector<domain::Contact> result;
    while (true) {
        const int rc = sqlite3_step(stmt.get());
        if (rc == SQLITE_ROW) {
            auto contact_opt = domain::Contact::from_json(column_text_string(stmt.get(), 0));
            if (!contact_opt.has_value()) {
                return application::ClientResult<std::vector<domain::Contact>>::error(
                    application::ClientError::storage("Corrupt contact JSON in SQLCipher store"));
            }
            result.push_back(std::move(*contact_opt));
        } else if (rc == SQLITE_DONE) {
            break;
        } else {
            return application::ClientResult<std::vector<domain::Contact>>::error(
                application::ClientError::storage(sqlite3_errmsg(db_)));
        }
    }
    return application::ClientResult<std::vector<domain::Contact>>::ok(std::move(result));
}

application::ClientResult<void> SqlCipherLocalStore::delete_contact(const domain::UserId& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<void>::error(application::ClientError::storage("Storage is closed"));
    }

    static constexpr const char* kSql = "DELETE FROM contacts WHERE user_id = ?1;";
    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    sqlite3_bind_text(stmt.get(), 1, user_id.value().c_str(), static_cast<int>(user_id.value().size()),
                      SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }
    if (sqlite3_changes(db_) == 0) {
        return application::ClientResult<void>::error(application::ClientError::storage("Contact not found"));
    }
    return application::ClientResult<void>::ok();
}

application::ClientResult<void> SqlCipherLocalStore::save_file_transfer(const domain::FileTransferRecord& record) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<void>::error(application::ClientError::storage("Storage is closed"));
    }
    if (record.transfer_id.empty() || record.file_id.empty() || record.conversation_id.empty()) {
        return application::ClientResult<void>::error(application::ClientError::validation(
            "Transfer ID, file ID, and conversation ID are required for file transfer persistence"));
    }

    static constexpr const char* kSql = R"sql(
        INSERT INTO file_transfers (transfer_id, conversation_id, updated_at_ms, payload_json)
        VALUES (?1, ?2, ?3, ?4)
        ON CONFLICT(transfer_id) DO UPDATE SET
            conversation_id = excluded.conversation_id,
            updated_at_ms = excluded.updated_at_ms,
            payload_json = excluded.payload_json;
    )sql";

    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    const std::string& cid = record.conversation_id.value();
    const std::string json = record.to_json();

    sqlite3_bind_text(stmt.get(), 1, record.transfer_id.c_str(), static_cast<int>(record.transfer_id.size()),
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, cid.c_str(), static_cast<int>(cid.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 3, static_cast<sqlite3_int64>(record.updated_at_ms));
    sqlite3_bind_text(stmt.get(), 4, json.c_str(), static_cast<int>(json.size()), SQLITE_TRANSIENT);

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }
    return application::ClientResult<void>::ok();
}

application::ClientResult<domain::FileTransferRecord>
SqlCipherLocalStore::get_file_transfer(std::string_view transfer_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<domain::FileTransferRecord>::error(
            application::ClientError::storage("Storage is closed"));
    }
    if (transfer_id.empty()) {
        return application::ClientResult<domain::FileTransferRecord>::error(
            application::ClientError::validation("Transfer ID cannot be empty"));
    }

    static constexpr const char* kSql = "SELECT payload_json FROM file_transfers WHERE transfer_id = ?1;";
    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<domain::FileTransferRecord>::error(
            application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    sqlite3_bind_text(stmt.get(), 1, transfer_id.data(), static_cast<int>(transfer_id.size()), SQLITE_TRANSIENT);
    const int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        auto rec_opt = domain::FileTransferRecord::from_json(column_text_string(stmt.get(), 0));
        if (!rec_opt.has_value()) {
            return application::ClientResult<domain::FileTransferRecord>::error(
                application::ClientError::storage("Corrupt file transfer JSON in SQLCipher store"));
        }
        return application::ClientResult<domain::FileTransferRecord>::ok(std::move(*rec_opt));
    }
    if (rc == SQLITE_DONE) {
        return application::ClientResult<domain::FileTransferRecord>::error(
            application::ClientError::storage("File transfer not found"));
    }
    return application::ClientResult<domain::FileTransferRecord>::error(
        application::ClientError::storage(sqlite3_errmsg(db_)));
}

application::ClientResult<std::vector<domain::FileTransferRecord>>
SqlCipherLocalStore::list_file_transfers(const domain::ConversationId& conversation_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<std::vector<domain::FileTransferRecord>>::error(
            application::ClientError::storage("Storage is closed"));
    }

    static constexpr const char* kSqlAll =
        "SELECT payload_json FROM file_transfers ORDER BY updated_at_ms DESC, transfer_id ASC;";
    static constexpr const char* kSqlByConv = "SELECT payload_json FROM file_transfers WHERE conversation_id = ?1 "
                                              "ORDER BY updated_at_ms DESC, transfer_id ASC;";

    const char* sql = conversation_id.empty() ? kSqlAll : kSqlByConv;
    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<std::vector<domain::FileTransferRecord>>::error(
            application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    if (!conversation_id.empty()) {
        sqlite3_bind_text(stmt.get(), 1, conversation_id.value().c_str(),
                          static_cast<int>(conversation_id.value().size()), SQLITE_TRANSIENT);
    }

    std::vector<domain::FileTransferRecord> result;
    while (true) {
        const int rc = sqlite3_step(stmt.get());
        if (rc == SQLITE_ROW) {
            auto rec_opt = domain::FileTransferRecord::from_json(column_text_string(stmt.get(), 0));
            if (!rec_opt.has_value()) {
                return application::ClientResult<std::vector<domain::FileTransferRecord>>::error(
                    application::ClientError::storage("Corrupt file transfer JSON in SQLCipher store"));
            }
            result.push_back(std::move(*rec_opt));
        } else if (rc == SQLITE_DONE) {
            break;
        } else {
            return application::ClientResult<std::vector<domain::FileTransferRecord>>::error(
                application::ClientError::storage(sqlite3_errmsg(db_)));
        }
    }
    return application::ClientResult<std::vector<domain::FileTransferRecord>>::ok(std::move(result));
}

application::ClientResult<void> SqlCipherLocalStore::delete_file_transfer(std::string_view transfer_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<void>::error(application::ClientError::storage("Storage is closed"));
    }
    if (transfer_id.empty()) {
        return application::ClientResult<void>::error(
            application::ClientError::validation("Transfer ID cannot be empty"));
    }

    static constexpr const char* kSql = "DELETE FROM file_transfers WHERE transfer_id = ?1;";
    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    sqlite3_bind_text(stmt.get(), 1, transfer_id.data(), static_cast<int>(transfer_id.size()), SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }
    if (sqlite3_changes(db_) == 0) {
        return application::ClientResult<void>::error(application::ClientError::storage("File transfer not found"));
    }
    return application::ClientResult<void>::ok();
}

application::ClientResult<void> SqlCipherLocalStore::save_outbox_record(const domain::OfflineOutboxRecord& record) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<void>::error(application::ClientError::storage("Storage is closed"));
    }
    if (record.outbox_id.empty() || record.conversation_id.empty() || record.payload_json.empty()) {
        return application::ClientResult<void>::error(application::ClientError::validation(
            "Outbox ID, conversation ID, and payload JSON are required for outbox persistence"));
    }

    static constexpr const char* kSql = R"sql(
        INSERT INTO offline_outbox (outbox_id, operation_type, conversation_id, priority, created_at_ms, payload_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        ON CONFLICT(outbox_id) DO UPDATE SET
            operation_type = excluded.operation_type,
            conversation_id = excluded.conversation_id,
            priority = excluded.priority,
            created_at_ms = excluded.created_at_ms,
            payload_json = excluded.payload_json;
    )sql";

    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    const std::string op_type(domain::to_string(record.operation_type));
    const std::string& cid = record.conversation_id.value();
    const std::string json = record.to_json();

    sqlite3_bind_text(stmt.get(), 1, record.outbox_id.c_str(), static_cast<int>(record.outbox_id.size()),
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, op_type.c_str(), static_cast<int>(op_type.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, cid.c_str(), static_cast<int>(cid.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 4, static_cast<sqlite3_int64>(record.priority));
    sqlite3_bind_int64(stmt.get(), 5, static_cast<sqlite3_int64>(record.created_at_ms));
    sqlite3_bind_text(stmt.get(), 6, json.c_str(), static_cast<int>(json.size()), SQLITE_TRANSIENT);

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }
    return application::ClientResult<void>::ok();
}

application::ClientResult<domain::OfflineOutboxRecord>
SqlCipherLocalStore::get_outbox_record(std::string_view outbox_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<domain::OfflineOutboxRecord>::error(
            application::ClientError::storage("Storage is closed"));
    }
    if (outbox_id.empty()) {
        return application::ClientResult<domain::OfflineOutboxRecord>::error(
            application::ClientError::validation("Outbox ID cannot be empty"));
    }

    static constexpr const char* kSql = "SELECT payload_json FROM offline_outbox WHERE outbox_id = ?1;";
    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<domain::OfflineOutboxRecord>::error(
            application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    sqlite3_bind_text(stmt.get(), 1, outbox_id.data(), static_cast<int>(outbox_id.size()), SQLITE_TRANSIENT);
    const int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        auto rec_opt = domain::OfflineOutboxRecord::from_json(column_text_string(stmt.get(), 0));
        if (!rec_opt.has_value()) {
            return application::ClientResult<domain::OfflineOutboxRecord>::error(
                application::ClientError::storage("Corrupt outbox record JSON in SQLCipher store"));
        }
        return application::ClientResult<domain::OfflineOutboxRecord>::ok(std::move(*rec_opt));
    }
    if (rc == SQLITE_DONE) {
        return application::ClientResult<domain::OfflineOutboxRecord>::error(
            application::ClientError::storage("Outbox record not found"));
    }
    return application::ClientResult<domain::OfflineOutboxRecord>::error(
        application::ClientError::storage(sqlite3_errmsg(db_)));
}

application::ClientResult<std::vector<domain::OfflineOutboxRecord>>
SqlCipherLocalStore::list_outbox_records(std::size_t limit) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<std::vector<domain::OfflineOutboxRecord>>::error(
            application::ClientError::storage("Storage is closed"));
    }

    static constexpr const char* kSql =
        "SELECT payload_json FROM offline_outbox ORDER BY priority DESC, created_at_ms ASC, outbox_id ASC LIMIT ?1;";
    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<std::vector<domain::OfflineOutboxRecord>>::error(
            application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    const std::size_t effective_limit = limit == 0U ? 500U : limit;
    sqlite3_bind_int64(stmt.get(), 1, static_cast<sqlite3_int64>(effective_limit));

    std::vector<domain::OfflineOutboxRecord> result;
    while (true) {
        const int rc = sqlite3_step(stmt.get());
        if (rc == SQLITE_ROW) {
            auto rec_opt = domain::OfflineOutboxRecord::from_json(column_text_string(stmt.get(), 0));
            if (!rec_opt.has_value()) {
                return application::ClientResult<std::vector<domain::OfflineOutboxRecord>>::error(
                    application::ClientError::storage("Corrupt outbox record JSON in SQLCipher store"));
            }
            result.push_back(std::move(*rec_opt));
        } else if (rc == SQLITE_DONE) {
            break;
        } else {
            return application::ClientResult<std::vector<domain::OfflineOutboxRecord>>::error(
                application::ClientError::storage(sqlite3_errmsg(db_)));
        }
    }
    return application::ClientResult<std::vector<domain::OfflineOutboxRecord>>::ok(std::move(result));
}

application::ClientResult<void> SqlCipherLocalStore::delete_outbox_record(std::string_view outbox_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<void>::error(application::ClientError::storage("Storage is closed"));
    }
    if (outbox_id.empty()) {
        return application::ClientResult<void>::error(
            application::ClientError::validation("Outbox ID cannot be empty"));
    }

    static constexpr const char* kSql = "DELETE FROM offline_outbox WHERE outbox_id = ?1;";
    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    sqlite3_bind_text(stmt.get(), 1, outbox_id.data(), static_cast<int>(outbox_id.size()), SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }
    if (sqlite3_changes(db_) == 0) {
        return application::ClientResult<void>::error(application::ClientError::storage("Outbox record not found"));
    }
    return application::ClientResult<void>::ok();
}

application::ClientResult<domain::SyncCursorRecord>
SqlCipherLocalStore::save_sync_cursor(const domain::SyncCursorRecord& cursor) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<domain::SyncCursorRecord>::error(
            application::ClientError::storage("Storage is closed"));
    }
    if (cursor.device_id.empty()) {
        return application::ClientResult<domain::SyncCursorRecord>::error(
            application::ClientError::validation("Device ID is required for save_sync_cursor"));
    }

    const std::string& did = cursor.device_id.value();
    const std::string& cid = cursor.conversation_id.value();

    domain::SyncCursorRecord effective = cursor;
    {
        static constexpr const char* kSelectSql =
            "SELECT payload_json FROM sync_cursors WHERE device_id = ?1 AND conversation_id = ?2;";
        StmtGuard select_stmt;
        if (sqlite3_prepare_v2(db_, kSelectSql, -1, select_stmt.out(), nullptr) != SQLITE_OK) {
            return application::ClientResult<domain::SyncCursorRecord>::error(
                application::ClientError::storage(sqlite3_errmsg(db_)));
        }
        sqlite3_bind_text(select_stmt.get(), 1, did.c_str(), static_cast<int>(did.size()), SQLITE_TRANSIENT);
        sqlite3_bind_text(select_stmt.get(), 2, cid.c_str(), static_cast<int>(cid.size()), SQLITE_TRANSIENT);

        const int rc = sqlite3_step(select_stmt.get());
        if (rc == SQLITE_ROW) {
            auto existing_opt = domain::SyncCursorRecord::from_json(column_text_string(select_stmt.get(), 0));
            if (!existing_opt.has_value()) {
                return application::ClientResult<domain::SyncCursorRecord>::error(
                    application::ClientError::storage("Corrupt sync cursor JSON in SQLCipher store"));
            }
            effective = *existing_opt;
            (void)effective.advance_monotonically(cursor.last_delivered_sequence, cursor.last_sync_timestamp_ms);
            if (cursor.last_delivered_sequence == existing_opt->last_delivered_sequence &&
                cursor.last_sync_timestamp_ms > effective.last_sync_timestamp_ms) {
                effective.last_sync_timestamp_ms = cursor.last_sync_timestamp_ms;
            }
            if (cursor.sync_version > effective.sync_version) {
                effective.sync_version = cursor.sync_version;
            }
        } else if (rc != SQLITE_DONE) {
            return application::ClientResult<domain::SyncCursorRecord>::error(
                application::ClientError::storage(sqlite3_errmsg(db_)));
        }
    }

    static constexpr const char* kUpsertSql = R"sql(
        INSERT INTO sync_cursors (device_id, conversation_id, last_delivered_sequence, updated_at_ms, payload_json)
        VALUES (?1, ?2, ?3, ?4, ?5)
        ON CONFLICT(device_id, conversation_id) DO UPDATE SET
            last_delivered_sequence = excluded.last_delivered_sequence,
            updated_at_ms = excluded.updated_at_ms,
            payload_json = excluded.payload_json;
    )sql";

    StmtGuard upsert_stmt;
    if (sqlite3_prepare_v2(db_, kUpsertSql, -1, upsert_stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<domain::SyncCursorRecord>::error(
            application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    const std::string json = effective.to_json();
    sqlite3_bind_text(upsert_stmt.get(), 1, did.c_str(), static_cast<int>(did.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(upsert_stmt.get(), 2, cid.c_str(), static_cast<int>(cid.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(upsert_stmt.get(), 3, static_cast<sqlite3_int64>(effective.last_delivered_sequence));
    sqlite3_bind_int64(upsert_stmt.get(), 4, static_cast<sqlite3_int64>(effective.last_sync_timestamp_ms));
    sqlite3_bind_text(upsert_stmt.get(), 5, json.c_str(), static_cast<int>(json.size()), SQLITE_TRANSIENT);

    if (sqlite3_step(upsert_stmt.get()) != SQLITE_DONE) {
        return application::ClientResult<domain::SyncCursorRecord>::error(
            application::ClientError::storage(sqlite3_errmsg(db_)));
    }
    return application::ClientResult<domain::SyncCursorRecord>::ok(std::move(effective));
}

application::ClientResult<domain::SyncCursorRecord>
SqlCipherLocalStore::get_sync_cursor(const domain::DeviceId& device_id, const domain::ConversationId& conversation_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<domain::SyncCursorRecord>::error(
            application::ClientError::storage("Storage is closed"));
    }
    if (device_id.empty()) {
        return application::ClientResult<domain::SyncCursorRecord>::error(
            application::ClientError::validation("Device ID is required for get_sync_cursor"));
    }

    static constexpr const char* kSql =
        "SELECT payload_json FROM sync_cursors WHERE device_id = ?1 AND conversation_id = ?2;";
    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<domain::SyncCursorRecord>::error(
            application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    const std::string& did = device_id.value();
    const std::string& cid = conversation_id.value();
    sqlite3_bind_text(stmt.get(), 1, did.c_str(), static_cast<int>(did.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, cid.c_str(), static_cast<int>(cid.size()), SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        auto rec_opt = domain::SyncCursorRecord::from_json(column_text_string(stmt.get(), 0));
        if (!rec_opt.has_value()) {
            return application::ClientResult<domain::SyncCursorRecord>::error(
                application::ClientError::storage("Corrupt sync cursor JSON in SQLCipher store"));
        }
        return application::ClientResult<domain::SyncCursorRecord>::ok(std::move(*rec_opt));
    }
    if (rc == SQLITE_DONE) {
        return application::ClientResult<domain::SyncCursorRecord>::ok(domain::SyncCursorRecord{
            .device_id = device_id,
            .conversation_id = conversation_id,
            .last_delivered_sequence = 0ULL,
            .last_sync_timestamp_ms = 0LL,
            .sync_version = 1,
        });
    }
    return application::ClientResult<domain::SyncCursorRecord>::error(
        application::ClientError::storage(sqlite3_errmsg(db_)));
}

application::ClientResult<std::vector<domain::SyncCursorRecord>>
SqlCipherLocalStore::list_sync_cursors(const domain::DeviceId& device_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<std::vector<domain::SyncCursorRecord>>::error(
            application::ClientError::storage("Storage is closed"));
    }
    if (device_id.empty()) {
        return application::ClientResult<std::vector<domain::SyncCursorRecord>>::error(
            application::ClientError::validation("Device ID is required for list_sync_cursors"));
    }

    static constexpr const char* kSql =
        "SELECT payload_json FROM sync_cursors WHERE device_id = ?1 ORDER BY conversation_id ASC;";
    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<std::vector<domain::SyncCursorRecord>>::error(
            application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    const std::string& did = device_id.value();
    sqlite3_bind_text(stmt.get(), 1, did.c_str(), static_cast<int>(did.size()), SQLITE_TRANSIENT);

    std::vector<domain::SyncCursorRecord> result;
    while (true) {
        const int rc = sqlite3_step(stmt.get());
        if (rc == SQLITE_ROW) {
            auto rec_opt = domain::SyncCursorRecord::from_json(column_text_string(stmt.get(), 0));
            if (!rec_opt.has_value()) {
                return application::ClientResult<std::vector<domain::SyncCursorRecord>>::error(
                    application::ClientError::storage("Corrupt sync cursor JSON in SQLCipher store"));
            }
            result.push_back(std::move(*rec_opt));
        } else if (rc == SQLITE_DONE) {
            break;
        } else {
            return application::ClientResult<std::vector<domain::SyncCursorRecord>>::error(
                application::ClientError::storage(sqlite3_errmsg(db_)));
        }
    }
    return application::ClientResult<std::vector<domain::SyncCursorRecord>>::ok(std::move(result));
}

application::ClientResult<void> SqlCipherLocalStore::save_user_profile(const domain::UserProfile& profile) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<void>::error(application::ClientError::storage("Storage is closed"));
    }

    const auto errors = profile.validate();
    if (!errors.empty()) {
        return application::ClientResult<void>::error(application::ClientError::validation(errors.front()));
    }

    static constexpr const char* kSql = R"sql(
        INSERT INTO user_profile (user_id, updated_at_ms, payload_json)
        VALUES (?1, ?2, ?3)
        ON CONFLICT(user_id) DO UPDATE SET
            updated_at_ms = excluded.updated_at_ms,
            payload_json = excluded.payload_json;
    )sql";

    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    const std::string& uid = profile.user_id.value();
    const std::string json = profile.to_json();
    sqlite3_bind_text(stmt.get(), 1, uid.c_str(), static_cast<int>(uid.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 2, static_cast<sqlite3_int64>(profile.updated_at_ms));
    sqlite3_bind_text(stmt.get(), 3, json.c_str(), static_cast<int>(json.size()), SQLITE_TRANSIENT);

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }
    return application::ClientResult<void>::ok();
}

application::ClientResult<std::optional<domain::UserProfile>>
SqlCipherLocalStore::get_user_profile(const domain::UserId& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<std::optional<domain::UserProfile>>::error(
            application::ClientError::storage("Storage is closed"));
    }
    if (user_id.empty()) {
        return application::ClientResult<std::optional<domain::UserProfile>>::error(
            application::ClientError::validation("User ID cannot be empty"));
    }

    static constexpr const char* kSql = "SELECT payload_json FROM user_profile WHERE user_id = ?1;";
    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<std::optional<domain::UserProfile>>::error(
            application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    const std::string& uid = user_id.value();
    sqlite3_bind_text(stmt.get(), 1, uid.c_str(), static_cast<int>(uid.size()), SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_DONE) {
        return application::ClientResult<std::optional<domain::UserProfile>>::ok(std::nullopt);
    }
    if (rc == SQLITE_ROW) {
        auto profile_opt = domain::UserProfile::from_json(column_text_string(stmt.get(), 0));
        if (!profile_opt.has_value()) {
            return application::ClientResult<std::optional<domain::UserProfile>>::error(
                application::ClientError::storage("Corrupt user_profile JSON in SQLCipher store"));
        }
        return application::ClientResult<std::optional<domain::UserProfile>>::ok(std::move(profile_opt));
    }
    return application::ClientResult<std::optional<domain::UserProfile>>::error(
        application::ClientError::storage(sqlite3_errmsg(db_)));
}

application::ClientResult<void> SqlCipherLocalStore::save_user_settings(std::string_view profile_key,
                                                                        const domain::UserSettings& settings) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<void>::error(application::ClientError::storage("Storage is closed"));
    }
    if (profile_key.empty()) {
        return application::ClientResult<void>::error(
            application::ClientError::validation("Settings profile_key cannot be empty"));
    }
    const auto errors = settings.validate();
    if (!errors.empty()) {
        return application::ClientResult<void>::error(application::ClientError::validation(errors.front()));
    }

    static constexpr const char* kSql = R"sql(
        INSERT INTO user_settings (profile_key, updated_at_ms, payload_json)
        VALUES (?1, ?2, ?3)
        ON CONFLICT(profile_key) DO UPDATE SET
            updated_at_ms = excluded.updated_at_ms,
            payload_json = excluded.payload_json;
    )sql";

    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    const std::string key_str(profile_key);
    const std::string json = settings.to_json();
    sqlite3_bind_text(stmt.get(), 1, key_str.c_str(), static_cast<int>(key_str.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 2, static_cast<sqlite3_int64>(settings.updated_at_ms));
    sqlite3_bind_text(stmt.get(), 3, json.c_str(), static_cast<int>(json.size()), SQLITE_TRANSIENT);

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        return application::ClientResult<void>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }
    return application::ClientResult<void>::ok();
}

application::ClientResult<std::optional<domain::UserSettings>>
SqlCipherLocalStore::get_user_settings(std::string_view profile_key) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<std::optional<domain::UserSettings>>::error(
            application::ClientError::storage("Storage is closed"));
    }
    if (profile_key.empty()) {
        return application::ClientResult<std::optional<domain::UserSettings>>::error(
            application::ClientError::validation("Settings profile_key cannot be empty"));
    }

    static constexpr const char* kSql = "SELECT payload_json FROM user_settings WHERE profile_key = ?1;";
    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<std::optional<domain::UserSettings>>::error(
            application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    const std::string key_str(profile_key);
    sqlite3_bind_text(stmt.get(), 1, key_str.c_str(), static_cast<int>(key_str.size()), SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_DONE) {
        return application::ClientResult<std::optional<domain::UserSettings>>::ok(std::nullopt);
    }
    if (rc == SQLITE_ROW) {
        auto settings_opt = domain::UserSettings::from_json(column_text_string(stmt.get(), 0));
        if (!settings_opt.has_value()) {
            return application::ClientResult<std::optional<domain::UserSettings>>::error(
                application::ClientError::storage("Corrupt user_settings JSON in SQLCipher store"));
        }
        return application::ClientResult<std::optional<domain::UserSettings>>::ok(std::move(settings_opt));
    }
    return application::ClientResult<std::optional<domain::UserSettings>>::error(
        application::ClientError::storage(sqlite3_errmsg(db_)));
}

application::ClientResult<std::size_t> SqlCipherLocalStore::delete_expired_messages(int64_t now_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_ == nullptr) {
        return application::ClientResult<std::size_t>::error(application::ClientError::storage("Storage is closed"));
    }
    if (now_ms <= 0) {
        return application::ClientResult<std::size_t>::ok(0U);
    }

    static constexpr const char* kSql = "DELETE FROM messages WHERE expires_at_ms > 0 AND expires_at_ms <= ?1;";
    StmtGuard stmt;
    if (sqlite3_prepare_v2(db_, kSql, -1, stmt.out(), nullptr) != SQLITE_OK) {
        return application::ClientResult<std::size_t>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }

    sqlite3_bind_int64(stmt.get(), 1, static_cast<sqlite3_int64>(now_ms));
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        return application::ClientResult<std::size_t>::error(application::ClientError::storage(sqlite3_errmsg(db_)));
    }
    return application::ClientResult<std::size_t>::ok(static_cast<std::size_t>(sqlite3_changes(db_)));
}

} // namespace securecloud::client::infrastructure::adapters
