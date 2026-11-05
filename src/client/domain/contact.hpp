#pragma once

#include "domain/crypto_identity.hpp"
#include "domain/user_id.hpp"

#include <chrono>
#include <string>

namespace securecloud::client::domain {

class Contact {
  public:
    Contact() = default;
    Contact(UserId user_id, std::string alias,
            KeyVerificationStatus verification_status = KeyVerificationStatus::Unverified,
            std::string identity_fingerprint = "", bool is_blocked = false,
            std::chrono::system_clock::time_point updated_at = std::chrono::system_clock::now());

    [[nodiscard]] const UserId& user_id() const noexcept { return user_id_; }
    [[nodiscard]] const std::string& alias() const noexcept { return alias_; }
    [[nodiscard]] KeyVerificationStatus verification_status() const noexcept { return verification_status_; }
    [[nodiscard]] const std::string& identity_fingerprint() const noexcept { return identity_fingerprint_; }
    [[nodiscard]] bool is_blocked() const noexcept { return is_blocked_; }
    [[nodiscard]] std::chrono::system_clock::time_point updated_at() const noexcept { return updated_at_; }

    void set_alias(std::string alias) { alias_ = std::move(alias); }
    void set_verification_status(KeyVerificationStatus status) noexcept { verification_status_ = status; }
    void set_identity_fingerprint(std::string fingerprint) { identity_fingerprint_ = std::move(fingerprint); }
    void set_blocked(bool blocked) noexcept { is_blocked_ = blocked; }
    void set_updated_at(std::chrono::system_clock::time_point tp) noexcept { updated_at_ = tp; }

    bool operator==(const Contact& other) const noexcept;
    bool operator!=(const Contact& other) const noexcept { return !(*this == other); }

  private:
    UserId user_id_;
    std::string alias_;
    KeyVerificationStatus verification_status_{KeyVerificationStatus::Unverified};
    std::string identity_fingerprint_;
    bool is_blocked_{false};
    std::chrono::system_clock::time_point updated_at_{std::chrono::system_clock::now()};
};

} // namespace securecloud::client::domain
