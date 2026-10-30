#include "messaging/repository/scylla_message_repository.hpp"

#include <chrono>
#include <stdexcept>

namespace securecloud::messaging::repository {
namespace {

inline int64_t to_millis(std::chrono::system_clock::time_point tp) noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
}

inline std::chrono::system_clock::time_point from_millis(int64_t ms) noexcept {
    return std::chrono::system_clock::time_point(std::chrono::milliseconds(ms));
}

domain::MessageEntity row_to_message_entity(const db::ScyllaRow& row) {
    domain::MessageEntity entity;

    auto opt_conv_id = domain::ConversationId::from_string(row.get_string("conversation_id"));
    if (opt_conv_id) {
        entity.conversation_id = *opt_conv_id;
    }

    auto opt_bucket = domain::MessageBucket::from_string(row.get_string("message_bucket"));
    if (opt_bucket) {
        entity.message_bucket = *opt_bucket;
    }

    entity.message_sequence = static_cast<uint64_t>(row.get_int64("message_sequence"));

    auto opt_msg_id = domain::MessageId::from_string(row.get_string("message_id"));
    if (opt_msg_id) {
        entity.message_id = *opt_msg_id;
    }

    entity.sender_user_id = domain::UserId(row.get_string("sender_user_id"));
    entity.sender_device_id = domain::DeviceId(row.get_string("sender_device_id"));

    auto opt_priority = domain::message_priority_from_string(row.get_string("message_priority"));
    entity.priority = opt_priority.value_or(domain::MessagePriority::Normal);

    entity.accepted_at = from_millis(row.get_timestamp("accepted_at"));

    entity.envelope.ciphertext = row.get_string("ciphertext_envelope");
    entity.envelope.envelope_version = row.get_int("envelope_version");

    if (!row.is_null("file_reference_ids")) {
        entity.file_reference_ids = row.get_string_list("file_reference_ids");
    }

    return entity;
}

} // namespace

ScyllaMessageRepository::ScyllaMessageRepository(std::shared_ptr<db::IScyllaSession> session)
    : session_(std::move(session)) {
    if (!session_) {
        throw std::invalid_argument("ScyllaMessageRepository requires non-null IScyllaSession");
    }
    init_prepared_statements();
}

void ScyllaMessageRepository::init_prepared_statements() {
    prep_save_message_ = session_->prepare(
        "msg_repo_save_message",
        "INSERT INTO securecloud_messaging.messages_by_conversation "
        "(conversation_id, message_bucket, message_sequence, message_id, sender_user_id, sender_device_id, "
        "message_priority, accepted_at, ciphertext_envelope, envelope_version, file_reference_ids) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");

    prep_find_by_id_ = session_->prepare(
        "msg_repo_find_by_id",
        "SELECT conversation_id, message_bucket, message_sequence, message_id, sender_user_id, sender_device_id, "
        "message_priority, accepted_at, ciphertext_envelope, envelope_version, file_reference_ids "
        "FROM securecloud_messaging.messages_by_conversation "
        "WHERE conversation_id = ? AND message_bucket = ? AND message_id = ?;");

    prep_list_range_ = session_->prepare(
        "msg_repo_list_range",
        "SELECT conversation_id, message_bucket, message_sequence, message_id, sender_user_id, sender_device_id, "
        "message_priority, accepted_at, ciphertext_envelope, envelope_version, file_reference_ids "
        "FROM securecloud_messaging.messages_by_conversation "
        "WHERE conversation_id = ? AND message_bucket = ? AND message_sequence >= ? AND message_sequence <= ? "
        "ORDER BY message_sequence ASC LIMIT ?;");

    prep_get_last_seq_ = session_->prepare(
        "msg_repo_get_last_seq", "SELECT message_sequence FROM securecloud_messaging.messages_by_conversation "
                                 "WHERE conversation_id = ? AND message_bucket = ? "
                                 "ORDER BY message_sequence DESC LIMIT 1;");
}

void ScyllaMessageRepository::save_message(const domain::MessageEntity& msg) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(msg.conversation_id.to_string());
    params.add_string(msg.message_bucket.value());
    params.add_int64(static_cast<int64_t>(msg.message_sequence));
    params.add_string(msg.message_id.to_string());
    params.add_string(msg.sender_user_id.str());
    params.add_string(msg.sender_device_id.str());
    params.add_string(domain::to_string(msg.priority));
    params.add_timestamp(to_millis(msg.accepted_at));
    params.add_string(msg.envelope.ciphertext);
    params.add_int(msg.envelope.envelope_version);
    params.add_string_list(msg.file_reference_ids);

    session_->execute_prepared(prep_save_message_, params);
}

std::optional<domain::MessageEntity> ScyllaMessageRepository::find_by_id(const domain::ConversationId& conversation_id,
                                                                         const domain::MessageBucket& message_bucket,
                                                                         const domain::MessageId& message_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(conversation_id.to_string());
    params.add_string(message_bucket.value());
    params.add_string(message_id.to_string());

    auto result = session_->execute_prepared(prep_find_by_id_, params);
    if (result.empty()) {
        return std::nullopt;
    }

    return row_to_message_entity(result.front());
}

std::vector<domain::MessageEntity>
ScyllaMessageRepository::list_messages_by_sequence_range(const domain::ConversationId& conversation_id,
                                                         const domain::MessageBucket& message_bucket,
                                                         uint64_t from_sequence, uint64_t to_sequence, size_t limit) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(conversation_id.to_string());
    params.add_string(message_bucket.value());
    params.add_int64(static_cast<int64_t>(from_sequence));
    params.add_int64(static_cast<int64_t>(to_sequence));
    params.add_int(static_cast<int32_t>(limit));

    auto result = session_->execute_prepared(prep_list_range_, params);

    std::vector<domain::MessageEntity> items;
    items.reserve(result.size());
    for (const auto& row : result) {
        items.push_back(row_to_message_entity(row));
    }
    return items;
}

uint64_t ScyllaMessageRepository::get_last_sequence(const domain::ConversationId& conversation_id,
                                                    const domain::MessageBucket& message_bucket) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(conversation_id.to_string());
    params.add_string(message_bucket.value());

    auto result = session_->execute_prepared(prep_get_last_seq_, params);
    if (result.empty()) {
        return 0;
    }

    return static_cast<uint64_t>(result.front().get_int64("message_sequence"));
}

} // namespace securecloud::messaging::repository
