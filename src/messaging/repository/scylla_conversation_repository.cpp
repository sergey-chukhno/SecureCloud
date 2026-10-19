#include "messaging/repository/scylla_conversation_repository.hpp"

#include <chrono>

namespace securecloud::messaging::repository {
namespace {

inline int64_t to_millis(std::chrono::system_clock::time_point tp) noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
}

inline std::chrono::system_clock::time_point from_millis(int64_t ms) noexcept {
    return std::chrono::system_clock::time_point(std::chrono::milliseconds(ms));
}

inline std::string conv_type_to_str(domain::ConversationType type) {
    switch (type) {
    case domain::ConversationType::Direct:
        return "DIRECT";
    case domain::ConversationType::Group:
        return "GROUP";
    }
    return "DIRECT";
}

inline domain::ConversationType conv_type_from_str(std::string_view str) {
    if (str == "GROUP") {
        return domain::ConversationType::Group;
    }
    return domain::ConversationType::Direct;
}

inline std::string group_status_to_str(domain::GroupStatus status) {
    switch (status) {
    case domain::GroupStatus::Active:
        return "ACTIVE";
    case domain::GroupStatus::Closed:
        return "CLOSED";
    }
    return "ACTIVE";
}

inline domain::GroupStatus group_status_from_str(std::string_view str) {
    if (str == "CLOSED") {
        return domain::GroupStatus::Closed;
    }
    return domain::GroupStatus::Active;
}

} // namespace

ScyllaConversationRepository::ScyllaConversationRepository(std::shared_ptr<db::IScyllaSession> session)
    : session_(std::move(session)) {
    if (!session_) {
        throw std::invalid_argument("ScyllaConversationRepository requires non-null IScyllaSession");
    }
    init_prepared_statements();
}

void ScyllaConversationRepository::init_prepared_statements() {
    prep_save_conv_ = session_->prepare(
        "conv_repo_save_conv", "INSERT INTO securecloud_messaging.conversations_by_id "
                               "(conversation_id, conversation_type, created_at, created_by_user_id, metadata_version) "
                               "VALUES (?, ?, ?, ?, ?);");

    prep_find_conv_ =
        session_->prepare("conv_repo_find_conv",
                          "SELECT conversation_id, conversation_type, created_at, created_by_user_id, metadata_version "
                          "FROM securecloud_messaging.conversations_by_id WHERE conversation_id = ?;");

    prep_save_direct_ = session_->prepare("conv_repo_save_direct",
                                          "INSERT INTO securecloud_messaging.direct_conversation_by_users "
                                          "(user_a_id, user_b_id, conversation_id, created_at) VALUES (?, ?, ?, ?);");

    prep_find_direct_ = session_->prepare(
        "conv_repo_find_direct", "SELECT conversation_id FROM securecloud_messaging.direct_conversation_by_users "
                                 "WHERE user_a_id = ? AND user_b_id = ?;");

    prep_save_group_meta_ = session_->prepare(
        "conv_repo_save_group_meta",
        "INSERT INTO securecloud_messaging.group_metadata_by_conversation "
        "(conversation_id, group_name, group_status, created_by_user_id, created_at, updated_at, metadata_version) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);");

    prep_find_group_meta_ =
        session_->prepare("conv_repo_find_group_meta",
                          "SELECT conversation_id, group_name, group_status, created_by_user_id, created_at, "
                          "updated_at, metadata_version "
                          "FROM securecloud_messaging.group_metadata_by_conversation WHERE conversation_id = ?;");
}

void ScyllaConversationRepository::save_conversation(const domain::ConversationEntity& conv) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(conv.conversation_id.to_string());
    params.add_string(conv_type_to_str(conv.type));
    params.add_timestamp(to_millis(conv.created_at));
    params.add_string(conv.created_by_user_id.str());
    params.add_int(static_cast<int32_t>(conv.metadata_version));

    session_->execute_prepared(prep_save_conv_, params);
}

std::optional<domain::ConversationEntity>
ScyllaConversationRepository::find_conversation_by_id(const domain::ConversationId& id) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(id.to_string());

    auto result = session_->execute_prepared(prep_find_conv_, params);
    if (result.empty()) {
        return std::nullopt;
    }

    const auto& row = result.front();
    domain::ConversationEntity entity;
    auto opt_id = domain::ConversationId::from_string(row.get_string("conversation_id"));
    entity.conversation_id = opt_id.value_or(id);
    entity.type = conv_type_from_str(row.get_string("conversation_type"));
    entity.created_by_user_id = domain::UserId(row.get_string("created_by_user_id"));
    entity.created_at = from_millis(row.get_timestamp("created_at"));
    entity.metadata_version = static_cast<uint64_t>(row.get_int("metadata_version"));

    return entity;
}

std::optional<domain::ConversationId>
ScyllaConversationRepository::find_direct_conversation(const domain::DirectPair& pair) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(pair.user_a().str());
    params.add_string(pair.user_b().str());

    auto result = session_->execute_prepared(prep_find_direct_, params);
    if (result.empty()) {
        return std::nullopt;
    }

    return domain::ConversationId::from_string(result.front().get_string("conversation_id"));
}

void ScyllaConversationRepository::save_direct_conversation(const domain::DirectPair& pair,
                                                            const domain::ConversationId& id) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(pair.user_a().str());
    params.add_string(pair.user_b().str());
    params.add_string(id.to_string());
    params.add_timestamp(to_millis(std::chrono::system_clock::now()));

    session_->execute_prepared(prep_save_direct_, params);
}

void ScyllaConversationRepository::save_group_metadata(const domain::GroupMetadataEntity& meta) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(meta.conversation_id.to_string());
    params.add_string(meta.title);
    params.add_string(group_status_to_str(meta.status));
    params.add_string(""); // created_by_user_id (optional in meta)
    params.add_timestamp(to_millis(meta.created_at));
    params.add_timestamp(to_millis(meta.updated_at));
    params.add_int(static_cast<int32_t>(meta.metadata_version));

    session_->execute_prepared(prep_save_group_meta_, params);
}

std::optional<domain::GroupMetadataEntity>
ScyllaConversationRepository::find_group_metadata(const domain::ConversationId& id) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(id.to_string());

    auto result = session_->execute_prepared(prep_find_group_meta_, params);
    if (result.empty()) {
        return std::nullopt;
    }

    const auto& row = result.front();
    domain::GroupMetadataEntity meta;
    auto opt_id = domain::ConversationId::from_string(row.get_string("conversation_id"));
    meta.conversation_id = opt_id.value_or(id);
    meta.title = row.get_string("group_name");
    meta.status = group_status_from_str(row.get_string("group_status"));
    meta.created_at = from_millis(row.get_timestamp("created_at"));
    meta.updated_at = from_millis(row.get_timestamp("updated_at"));
    meta.metadata_version = static_cast<uint64_t>(row.get_int("metadata_version"));

    return meta;
}

} // namespace securecloud::messaging::repository
