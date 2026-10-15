#include "messaging/repository/scylla_membership_repository.hpp"

#include <algorithm>
#include <chrono>

namespace securecloud::messaging::repository {
namespace {

inline int64_t to_millis(std::chrono::system_clock::time_point tp) noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
}

inline std::chrono::system_clock::time_point from_millis(int64_t ms) noexcept {
    return std::chrono::system_clock::time_point(std::chrono::milliseconds(ms));
}

inline std::string membership_status_to_str(domain::MembershipStatus status) {
    switch (status) {
    case domain::MembershipStatus::Active:
        return "ACTIVE";
    case domain::MembershipStatus::Left:
        return "LEFT";
    case domain::MembershipStatus::Removed:
        return "REMOVED";
    }
    return "ACTIVE";
}

inline domain::MembershipStatus membership_status_from_str(std::string_view str) {
    if (str == "LEFT") {
        return domain::MembershipStatus::Left;
    }
    if (str == "REMOVED") {
        return domain::MembershipStatus::Removed;
    }
    return domain::MembershipStatus::Active;
}

inline std::string participant_role_to_str(domain::ParticipantRole role) {
    switch (role) {
    case domain::ParticipantRole::Member:
        return "MEMBER";
    case domain::ParticipantRole::Admin:
        return "ADMIN";
    }
    return "MEMBER";
}

inline domain::ParticipantRole participant_role_from_str(std::string_view str) {
    if (str == "ADMIN") {
        return domain::ParticipantRole::Admin;
    }
    return domain::ParticipantRole::Member;
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

} // namespace

ScyllaMembershipRepository::ScyllaMembershipRepository(std::shared_ptr<db::IScyllaSession> session)
    : session_(std::move(session)) {
    if (!session_) {
        throw std::invalid_argument("ScyllaMembershipRepository requires non-null IScyllaSession");
    }
    init_prepared_statements();
}

void ScyllaMembershipRepository::init_prepared_statements() {
    prep_save_member_ =
        session_->prepare("member_repo_save_member",
                          "INSERT INTO securecloud_messaging.conversation_members_by_conversation "
                          "(conversation_id, user_id, membership_status, role, joined_at, left_at, membership_version) "
                          "VALUES (?, ?, ?, ?, ?, ?, ?);");

    prep_find_member_ = session_->prepare(
        "member_repo_find_member",
        "SELECT conversation_id, user_id, membership_status, role, joined_at, left_at, membership_version "
        "FROM securecloud_messaging.conversation_members_by_conversation "
        "WHERE conversation_id = ? AND user_id = ?;");

    prep_list_members_ = session_->prepare(
        "member_repo_list_members",
        "SELECT conversation_id, user_id, membership_status, role, joined_at, left_at, membership_version "
        "FROM securecloud_messaging.conversation_members_by_conversation "
        "WHERE conversation_id = ?;");

    prep_touch_user_conv_ = session_->prepare(
        "member_repo_touch_user_conv",
        "INSERT INTO securecloud_messaging.conversations_by_user "
        "(user_id, last_activity_at, conversation_id, conversation_type, membership_status, unread_state_version) "
        "VALUES (?, ?, ?, ?, ?, ?);");

    prep_list_user_convs_ = session_->prepare(
        "member_repo_list_user_convs", "SELECT conversation_id, conversation_type, membership_status, last_activity_at "
                                       "FROM securecloud_messaging.conversations_by_user WHERE user_id = ?;");
}

void ScyllaMembershipRepository::add_participant(const domain::ConversationParticipantEntity& participant) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(participant.conversation_id.to_string());
    params.add_string(participant.user_id.str());
    params.add_string(membership_status_to_str(participant.status));
    params.add_string(participant_role_to_str(participant.role));
    params.add_timestamp(to_millis(participant.joined_at));

    if (participant.left_at.has_value()) {
        params.add_timestamp(to_millis(participant.left_at.value()));
    } else {
        params.add_null();
    }
    params.add_int(static_cast<int32_t>(participant.membership_version));

    session_->execute_prepared(prep_save_member_, params);
}

void ScyllaMembershipRepository::update_participant(const domain::ConversationParticipantEntity& participant) {
    // In ScyllaDB, INSERT into conversation_members_by_conversation is an upsert updating columns
    add_participant(participant);
}

std::optional<domain::ConversationParticipantEntity>
ScyllaMembershipRepository::find_participant(const domain::ConversationId& conv_id, const domain::UserId& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(conv_id.to_string());
    params.add_string(user_id.str());

    auto result = session_->execute_prepared(prep_find_member_, params);
    if (result.empty()) {
        return std::nullopt;
    }

    const auto& row = result.front();
    domain::ConversationParticipantEntity entity;
    auto opt_id = domain::ConversationId::from_string(row.get_string("conversation_id"));
    entity.conversation_id = opt_id.value_or(conv_id);
    entity.user_id = domain::UserId(row.get_string("user_id"));
    entity.status = membership_status_from_str(row.get_string("membership_status"));
    entity.role = participant_role_from_str(row.get_string("role"));
    entity.joined_at = from_millis(row.get_timestamp("joined_at"));
    if (!row.is_null("left_at")) {
        entity.left_at = from_millis(row.get_timestamp("left_at"));
    }
    entity.membership_version = static_cast<uint64_t>(row.get_int("membership_version"));

    return entity;
}

std::vector<domain::ConversationParticipantEntity>
ScyllaMembershipRepository::list_participants(const domain::ConversationId& conv_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(conv_id.to_string());

    auto result = session_->execute_prepared(prep_list_members_, params);
    std::vector<domain::ConversationParticipantEntity> list;
    list.reserve(result.size());

    for (const auto& row : result) {
        domain::ConversationParticipantEntity entity;
        auto opt_id = domain::ConversationId::from_string(row.get_string("conversation_id"));
        entity.conversation_id = opt_id.value_or(conv_id);
        entity.user_id = domain::UserId(row.get_string("user_id"));
        entity.status = membership_status_from_str(row.get_string("membership_status"));
        entity.role = participant_role_from_str(row.get_string("role"));
        entity.joined_at = from_millis(row.get_timestamp("joined_at"));
        if (!row.is_null("left_at")) {
            entity.left_at = from_millis(row.get_timestamp("left_at"));
        }
        entity.membership_version = static_cast<uint64_t>(row.get_int("membership_version"));
        list.push_back(std::move(entity));
    }

    return list;
}

std::vector<domain::ConversationParticipantEntity>
ScyllaMembershipRepository::list_active_participants(const domain::ConversationId& conv_id) {
    auto all = list_participants(conv_id);
    std::vector<domain::ConversationParticipantEntity> active;
    for (auto& p : all) {
        if (p.status == domain::MembershipStatus::Active) {
            active.push_back(std::move(p));
        }
    }
    return active;
}

void ScyllaMembershipRepository::touch_user_conversation(const domain::UserId& user_id,
                                                         const domain::ConversationId& conv_id,
                                                         domain::ConversationType type, domain::MembershipStatus status,
                                                         std::chrono::system_clock::time_point activity_at) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(user_id.str());
    params.add_timestamp(to_millis(activity_at));
    params.add_string(conv_id.to_string());
    params.add_string(conv_type_to_str(type));
    params.add_string(membership_status_to_str(status));
    params.add_int(1); // unread_state_version

    session_->execute_prepared(prep_touch_user_conv_, params);
}

UserConversationsPage
ScyllaMembershipRepository::list_user_conversations(const domain::UserId& user_id, int limit,
                                                    const std::optional<std::string>& page_token) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(user_id.str());

    auto result = session_->execute_prepared(prep_list_user_convs_, params);

    std::vector<UserConversationSummary> all_items;
    all_items.reserve(result.size());

    for (const auto& row : result) {
        UserConversationSummary summary;
        auto opt_id = domain::ConversationId::from_string(row.get_string("conversation_id"));
        summary.conversation_id = opt_id.value_or(domain::ConversationId{});
        summary.type = conv_type_from_str(row.get_string("conversation_type"));
        summary.membership_status = membership_status_from_str(row.get_string("membership_status"));
        summary.last_activity_at = from_millis(row.get_timestamp("last_activity_at"));
        all_items.push_back(std::move(summary));
    }

    // Sort descending by last_activity_at
    std::sort(all_items.begin(), all_items.end(),
              [](const UserConversationSummary& a, const UserConversationSummary& b) {
                  return a.last_activity_at > b.last_activity_at;
              });

    // Handle pagination cursor offset
    std::size_t start_idx = 0;
    if (page_token.has_value() && !page_token.value().empty()) {
        try {
            start_idx = std::stoul(page_token.value());
        } catch (...) {
            start_idx = 0;
        }
    }

    UserConversationsPage page;
    const std::size_t page_limit = (limit > 0) ? static_cast<std::size_t>(limit) : 50U;
    const std::size_t end_idx = std::min(start_idx + page_limit, all_items.size());

    for (std::size_t i = start_idx; i < end_idx; ++i) {
        page.items.push_back(all_items[i]);
    }

    if (end_idx < all_items.size()) {
        page.next_page_token = std::to_string(end_idx);
    }

    return page;
}

} // namespace securecloud::messaging::repository
