#include "domain/contact.hpp"

#include <utility>

namespace securecloud::client::domain {

Contact::Contact(UserId user_id, std::string alias, KeyVerificationStatus verification_status,
                 std::string identity_fingerprint, bool is_blocked, std::chrono::system_clock::time_point updated_at)
    : user_id_(std::move(user_id)), alias_(std::move(alias)), verification_status_(verification_status),
      identity_fingerprint_(std::move(identity_fingerprint)), is_blocked_(is_blocked), updated_at_(updated_at) {}

bool Contact::operator==(const Contact& other) const noexcept {
    return user_id_ == other.user_id_ && alias_ == other.alias_ && verification_status_ == other.verification_status_ &&
           identity_fingerprint_ == other.identity_fingerprint_ && is_blocked_ == other.is_blocked_;
}

} // namespace securecloud::client::domain
