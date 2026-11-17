#include "domain/conversation.hpp"

#include <algorithm>
#include <nlohmann/json.hpp>
#include <utility>

namespace securecloud::client::domain {

std::string_view to_string(ConversationType type) noexcept {
    switch (type) {
    case ConversationType::Direct:
        return "Direct";
    case ConversationType::Group:
        return "Group";
    }
    return "Unknown";
}

std::optional<ConversationType> conversation_type_from_string(std::string_view str) noexcept {
    if (str == "Direct") {
        return ConversationType::Direct;
    }
    if (str == "Group") {
        return ConversationType::Group;
    }
    return std::nullopt;
}

std::string_view to_string(GroupStatus status) noexcept {
    switch (status) {
    case GroupStatus::Active:
        return "Active";
    case GroupStatus::Closed:
        return "Closed";
    }
    return "Active";
}

std::optional<GroupStatus> group_status_from_string(std::string_view str) noexcept {
    if (str == "Active") {
        return GroupStatus::Active;
    }
    if (str == "Closed") {
        return GroupStatus::Closed;
    }
    return std::nullopt;
}

std::string_view to_string(MembershipStatus status) noexcept {
    switch (status) {
    case MembershipStatus::Active:
        return "Active";
    case MembershipStatus::Left:
        return "Left";
    case MembershipStatus::Removed:
        return "Removed";
    }
    return "Active";
}

std::optional<MembershipStatus> membership_status_from_string(std::string_view str) noexcept {
    if (str == "Active") {
        return MembershipStatus::Active;
    }
    if (str == "Left") {
        return MembershipStatus::Left;
    }
    if (str == "Removed") {
        return MembershipStatus::Removed;
    }
    return std::nullopt;
}

std::string_view to_string(ParticipantRole role) noexcept {
    switch (role) {
    case ParticipantRole::Member:
        return "Member";
    case ParticipantRole::Admin:
        return "Admin";
    }
    return "Member";
}

std::optional<ParticipantRole> participant_role_from_string(std::string_view str) noexcept {
    if (str == "Member") {
        return ParticipantRole::Member;
    }
    if (str == "Admin") {
        return ParticipantRole::Admin;
    }
    return std::nullopt;
}

bool GroupParticipant::operator==(const GroupParticipant& other) const noexcept {
    const auto lhs_ms = std::chrono::duration_cast<std::chrono::milliseconds>(joined_at.time_since_epoch()).count();
    const auto rhs_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(other.joined_at.time_since_epoch()).count();
    return user_id == other.user_id && role == other.role && status == other.status && lhs_ms == rhs_ms &&
           membership_version == other.membership_version;
}

Conversation::Conversation(ConversationId conversation_id, ConversationType type, std::string title,
                           std::vector<UserId> participants, std::chrono::system_clock::time_point created_at,
                           std::chrono::system_clock::time_point last_activity_at, uint32_t unread_count, bool is_muted)
    : conversation_id_(std::move(conversation_id)), type_(type), title_(std::move(title)),
      participants_(std::move(participants)), created_at_(created_at), last_activity_at_(last_activity_at),
      unread_count_(unread_count), is_muted_(is_muted) {
    participant_records_.reserve(participants_.size());
    for (const auto& uid : participants_) {
        participant_records_.push_back(GroupParticipant{
            .user_id = uid,
            .role = ParticipantRole::Member,
            .status = MembershipStatus::Active,
            .joined_at = created_at_,
            .membership_version = 1,
        });
    }
}

void Conversation::sync_active_participants() {
    participants_.clear();
    for (const auto& rec : participant_records_) {
        if (rec.status == MembershipStatus::Active) {
            participants_.push_back(rec.user_id);
        }
    }
}

void Conversation::add_participant(UserId user_id) {
    add_participant(std::move(user_id), ParticipantRole::Member);
}

void Conversation::add_participant(UserId user_id, ParticipantRole role) {
    for (auto& rec : participant_records_) {
        if (rec.user_id == user_id) {
            if (rec.status != MembershipStatus::Active) {
                rec.status = MembershipStatus::Active;
                rec.role = role;
                rec.joined_at = std::chrono::system_clock::now();
                ++rec.membership_version;
                sync_active_participants();
            }
            return;
        }
    }

    participant_records_.push_back(GroupParticipant{
        .user_id = std::move(user_id),
        .role = role,
        .status = MembershipStatus::Active,
        .joined_at = std::chrono::system_clock::now(),
        .membership_version = 1,
    });
    sync_active_participants();
}

void Conversation::remove_participant(const UserId& user_id) {
    set_participant_status(user_id, MembershipStatus::Removed);
}

bool Conversation::has_participant(const UserId& user_id) const noexcept {
    return std::find(participants_.begin(), participants_.end(), user_id) != participants_.end();
}

std::optional<GroupParticipant> Conversation::find_participant(const UserId& user_id) const noexcept {
    for (const auto& rec : participant_records_) {
        if (rec.user_id == user_id) {
            return rec;
        }
    }
    return std::nullopt;
}

std::optional<ParticipantRole> Conversation::role_of(const UserId& user_id) const noexcept {
    for (const auto& rec : participant_records_) {
        if (rec.user_id == user_id && rec.status == MembershipStatus::Active) {
            return rec.role;
        }
    }
    return std::nullopt;
}

bool Conversation::is_admin(const UserId& user_id) const noexcept {
    const auto r = role_of(user_id);
    return r.has_value() && *r == ParticipantRole::Admin;
}

bool Conversation::set_participant_role(const UserId& user_id, ParticipantRole role) {
    for (auto& rec : participant_records_) {
        if (rec.user_id == user_id && rec.status == MembershipStatus::Active) {
            rec.role = role;
            ++rec.membership_version;
            return true;
        }
    }
    return false;
}

bool Conversation::set_participant_status(const UserId& user_id, MembershipStatus status) {
    for (auto& rec : participant_records_) {
        if (rec.user_id == user_id) {
            if (rec.status != status) {
                rec.status = status;
                ++rec.membership_version;
                sync_active_participants();
            }
            return true;
        }
    }
    return false;
}

void Conversation::set_participant_records(std::vector<GroupParticipant> records) {
    participant_records_ = std::move(records);
    sync_active_participants();
}

std::string Conversation::to_json() const {
    nlohmann::json j;
    j["conversation_id"] = conversation_id_.value();
    j["type"] = std::string(to_string(type_));
    j["title"] = title_;
    j["group_status"] = std::string(to_string(group_status_));
    j["sender_key_epoch"] = sender_key_epoch_;
    j["created_at_ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(created_at_.time_since_epoch()).count();
    j["last_activity_at_ms"] =
        std::chrono::duration_cast<std::chrono::milliseconds>(last_activity_at_.time_since_epoch()).count();
    j["unread_count"] = unread_count_;
    j["is_muted"] = is_muted_;

    nlohmann::json recs = nlohmann::json::array();
    for (const auto& rec : participant_records_) {
        recs.push_back({
            {"user_id", rec.user_id.str()},
            {"role", std::string(to_string(rec.role))},
            {"status", std::string(to_string(rec.status))},
            {"joined_at_ms",
             std::chrono::duration_cast<std::chrono::milliseconds>(rec.joined_at.time_since_epoch()).count()},
            {"membership_version", rec.membership_version},
        });
    }
    j["participant_records"] = std::move(recs);
    return j.dump();
}

std::optional<Conversation> Conversation::from_json(std::string_view json_str) {
    try {
        const auto j = nlohmann::json::parse(json_str);
        if (!j.is_object() || !j.contains("conversation_id") || !j["conversation_id"].is_string()) {
            return std::nullopt;
        }

        const std::string cid_str = j["conversation_id"].get<std::string>();
        if (cid_str.empty()) {
            return std::nullopt;
        }
        const ConversationId cid(cid_str);

        const std::string type_str = j.value("type", "Direct");
        const auto type_opt = conversation_type_from_string(type_str);
        if (!type_opt.has_value()) {
            return std::nullopt;
        }

        const std::string title = j.value("title", "");
        const uint32_t unread_count = j.value("unread_count", 0u);
        const bool is_muted = j.value("is_muted", false);

        auto created_at = std::chrono::system_clock::now();
        if (j.contains("created_at_ms") && j["created_at_ms"].is_number_integer()) {
            created_at =
                std::chrono::system_clock::time_point(std::chrono::milliseconds(j["created_at_ms"].get<int64_t>()));
        }

        auto last_activity_at = created_at;
        if (j.contains("last_activity_at_ms") && j["last_activity_at_ms"].is_number_integer()) {
            last_activity_at = std::chrono::system_clock::time_point(
                std::chrono::milliseconds(j["last_activity_at_ms"].get<int64_t>()));
        }

        Conversation conv(cid, *type_opt, title, {}, created_at, last_activity_at, unread_count, is_muted);

        if (j.contains("group_status") && j["group_status"].is_string()) {
            const auto gs_opt = group_status_from_string(j["group_status"].get<std::string>());
            if (!gs_opt.has_value()) {
                return std::nullopt;
            }
            conv.set_group_status(*gs_opt);
        }

        if (j.contains("sender_key_epoch") && j["sender_key_epoch"].is_number_unsigned()) {
            conv.set_sender_key_epoch(j["sender_key_epoch"].get<uint64_t>());
        }

        if (j.contains("participant_records") && j["participant_records"].is_array()) {
            std::vector<GroupParticipant> records;
            records.reserve(j["participant_records"].size());
            for (const auto& item : j["participant_records"]) {
                if (!item.is_object() || !item.contains("user_id") || !item["user_id"].is_string()) {
                    return std::nullopt;
                }
                const auto role_opt = participant_role_from_string(item.value("role", "Member"));
                const auto status_opt = membership_status_from_string(item.value("status", "Active"));
                if (!role_opt.has_value() || !status_opt.has_value()) {
                    return std::nullopt;
                }
                auto joined_at = created_at;
                if (item.contains("joined_at_ms") && item["joined_at_ms"].is_number_integer()) {
                    joined_at = std::chrono::system_clock::time_point(
                        std::chrono::milliseconds(item["joined_at_ms"].get<int64_t>()));
                }
                records.push_back(GroupParticipant{
                    .user_id = UserId(item["user_id"].get<std::string>()),
                    .role = *role_opt,
                    .status = *status_opt,
                    .joined_at = joined_at,
                    .membership_version = item.value("membership_version", uint64_t{1}),
                });
            }
            conv.set_participant_records(std::move(records));
        }

        return conv;
    } catch (...) {
        return std::nullopt;
    }
}

bool Conversation::operator==(const Conversation& other) const noexcept {
    return conversation_id_ == other.conversation_id_ && type_ == other.type_ && title_ == other.title_ &&
           participants_ == other.participants_ && unread_count_ == other.unread_count_ &&
           is_muted_ == other.is_muted_ && group_status_ == other.group_status_ &&
           sender_key_epoch_ == other.sender_key_epoch_;
}

} // namespace securecloud::client::domain
