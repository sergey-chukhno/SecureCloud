#include "domain/contact.hpp"

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

Contact::Contact(UserId user_id, std::string alias, KeyVerificationStatus verification_status,
                 std::string identity_fingerprint, bool is_blocked, std::chrono::system_clock::time_point updated_at)
    : user_id_(std::move(user_id)), alias_(std::move(alias)), verification_status_(verification_status),
      identity_fingerprint_(std::move(identity_fingerprint)), is_blocked_(is_blocked), updated_at_(updated_at) {}

Contact::Contact(UserId user_id, std::string alias, KeyVerificationStatus verification_status,
                 std::string identity_fingerprint, bool is_blocked, std::string safety_number, std::string role_note,
                 PresenceStatus presence_status, uint32_t authorized_device_count,
                 std::chrono::system_clock::time_point updated_at)
    : user_id_(std::move(user_id)), alias_(std::move(alias)), verification_status_(verification_status),
      identity_fingerprint_(std::move(identity_fingerprint)), is_blocked_(is_blocked),
      safety_number_(std::move(safety_number)), role_note_(std::move(role_note)), presence_status_(presence_status),
      authorized_device_count_(authorized_device_count), updated_at_(updated_at) {}

bool Contact::operator==(const Contact& other) const noexcept {
    return user_id_ == other.user_id_ && alias_ == other.alias_ && verification_status_ == other.verification_status_ &&
           identity_fingerprint_ == other.identity_fingerprint_ && is_blocked_ == other.is_blocked_ &&
           safety_number_ == other.safety_number_ && role_note_ == other.role_note_ &&
           presence_status_ == other.presence_status_ && authorized_device_count_ == other.authorized_device_count_;
}

} // namespace securecloud::client::domain
