#include "domain/contact.hpp"

#include <nlohmann/json.hpp>
#include <utility>

namespace securecloud::client::domain {

std::string_view to_string(PresenceStatus status) noexcept {
    switch (status) {
    case PresenceStatus::Online:
        return "Online";
    case PresenceStatus::Away:
        return "Away";
    case PresenceStatus::Offline:
        return "Offline";
    }
    return "Offline";
}

std::optional<PresenceStatus> presence_status_from_string(std::string_view str) noexcept {
    if (str == "Online") {
        return PresenceStatus::Online;
    }
    if (str == "Away") {
        return PresenceStatus::Away;
    }
    if (str == "Offline") {
        return PresenceStatus::Offline;
    }
    return std::nullopt;
}

Contact::Contact(UserId user_id, std::string alias, KeyVerificationStatus verification_status,
                 std::string identity_fingerprint, bool is_blocked, std::chrono::system_clock::time_point updated_at)
    : user_id_(std::move(user_id)), alias_(std::move(alias)), verification_status_(verification_status),
      identity_fingerprint_(std::move(identity_fingerprint)), is_blocked_(is_blocked), updated_at_(updated_at) {}

Contact::Contact(UserId user_id, std::string alias, KeyVerificationStatus verification_status,
                 std::string identity_fingerprint, bool is_blocked, std::string safety_number, std::string role_note,
                 PresenceStatus presence_status, uint32_t authorized_device_count,
                 std::chrono::system_clock::time_point updated_at,
                 std::optional<std::chrono::system_clock::time_point> last_seen_at)
    : user_id_(std::move(user_id)), alias_(std::move(alias)), verification_status_(verification_status),
      identity_fingerprint_(std::move(identity_fingerprint)), is_blocked_(is_blocked),
      safety_number_(std::move(safety_number)), role_note_(std::move(role_note)), presence_status_(presence_status),
      authorized_device_count_(authorized_device_count), updated_at_(updated_at), last_seen_at_(last_seen_at) {}

std::string Contact::to_json() const {
    nlohmann::json j;
    j["user_id"] = user_id_.value();
    j["alias"] = alias_;
    j["verification_status"] = std::string(to_string(verification_status_));
    j["identity_fingerprint"] = identity_fingerprint_;
    j["is_blocked"] = is_blocked_;
    j["safety_number"] = safety_number_;
    j["role_note"] = role_note_;
    j["presence_status"] = std::string(to_string(presence_status_));
    j["authorized_device_count"] = authorized_device_count_;

    const auto updated_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(updated_at_.time_since_epoch()).count();
    j["updated_at_ms"] = updated_ms;

    if (last_seen_at_.has_value()) {
        const auto last_seen_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(last_seen_at_->time_since_epoch()).count();
        j["last_seen_at_ms"] = last_seen_ms;
    } else {
        j["last_seen_at_ms"] = nullptr;
    }

    return j.dump();
}

std::optional<Contact> Contact::from_json(std::string_view json_str) {
    try {
        const auto j = nlohmann::json::parse(json_str);
        if (!j.contains("user_id") || !j["user_id"].is_string()) {
            return std::nullopt;
        }

        const UserId uid(j["user_id"].get<std::string>());
        const std::string alias = j.value("alias", "");
        const std::string status_str = j.value("verification_status", "Unverified");
        const auto ver_status =
            key_verification_status_from_string(status_str).value_or(KeyVerificationStatus::Unverified);
        const std::string fingerprint = j.value("identity_fingerprint", "");
        const bool blocked = j.value("is_blocked", false);
        const std::string safety_num = j.value("safety_number", "");
        const std::string note = j.value("role_note", "");
        const std::string presence_str = j.value("presence_status", "Offline");
        const auto presence = presence_status_from_string(presence_str).value_or(PresenceStatus::Offline);
        const uint32_t device_count = j.value("authorized_device_count", 1u);

        std::chrono::system_clock::time_point updated_at = std::chrono::system_clock::now();
        if (j.contains("updated_at_ms") && j["updated_at_ms"].is_number()) {
            updated_at =
                std::chrono::system_clock::time_point(std::chrono::milliseconds(j["updated_at_ms"].get<int64_t>()));
        }

        std::optional<std::chrono::system_clock::time_point> last_seen_at = std::nullopt;
        if (j.contains("last_seen_at_ms") && j["last_seen_at_ms"].is_number()) {
            last_seen_at =
                std::chrono::system_clock::time_point(std::chrono::milliseconds(j["last_seen_at_ms"].get<int64_t>()));
        }

        return Contact(uid, alias, ver_status, fingerprint, blocked, safety_num, note, presence, device_count,
                       updated_at, last_seen_at);
    } catch (...) {
        return std::nullopt;
    }
}

bool Contact::operator==(const Contact& other) const noexcept {
    return user_id_ == other.user_id_ && alias_ == other.alias_ && verification_status_ == other.verification_status_ &&
           identity_fingerprint_ == other.identity_fingerprint_ && is_blocked_ == other.is_blocked_ &&
           safety_number_ == other.safety_number_ && role_note_ == other.role_note_ &&
           presence_status_ == other.presence_status_ && authorized_device_count_ == other.authorized_device_count_ &&
           last_seen_at_ == other.last_seen_at_;
}

} // namespace securecloud::client::domain
