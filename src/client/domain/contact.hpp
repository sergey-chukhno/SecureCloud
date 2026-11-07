#pragma once

#include "domain/crypto_identity.hpp"
#include "domain/user_id.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>

namespace securecloud::client::domain {

enum class PresenceStatus { Online, Away, Offline };

[[nodiscard]] std::string_view to_string(PresenceStatus status) noexcept;

class Contact {
  public:
    Contact() = default;
    Contact(UserId user_id, std::string alias,
            KeyVerificationStatus verification_status = KeyVerificationStatus::Unverified,
            std::string identity_fingerprint = "", bool is_blocked = false,
            std::chrono::system_clock::time_point updated_at = std::chrono::system_clock::now());

    Contact(UserId user_id, std::string alias, KeyVerificationStatus verification_status,
            std::string identity_fingerprint, bool is_blocked, std::string safety_number, std::string role_note,
            PresenceStatus presence_status = PresenceStatus::Offline, uint32_t authorized_device_count = 1,
            std::chrono::system_clock::time_point updated_at = std::chrono::system_clock::now());

    [[nodiscard]] const UserId& user_id() const noexcept { return user_id_; }
    [[nodiscard]] const std::string& alias() const noexcept { return alias_; }
    [[nodiscard]] KeyVerificationStatus verification_status() const noexcept { return verification_status_; }
    [[nodiscard]] const std::string& identity_fingerprint() const noexcept { return identity_fingerprint_; }
    [[nodiscard]] bool is_blocked() const noexcept { return is_blocked_; }
    [[nodiscard]] const std::string& safety_number() const noexcept { return safety_number_; }
    [[nodiscard]] const std::string& role_note() const noexcept { return role_note_; }
    [[nodiscard]] PresenceStatus presence_status() const noexcept { return presence_status_; }
    [[nodiscard]] uint32_t authorized_device_count() const noexcept { return authorized_device_count_; }
    [[nodiscard]] std::chrono::system_clock::time_point updated_at() const noexcept { return updated_at_; }

    void set_alias(std::string alias) { alias_ = std::move(alias); }
    void set_verification_status(KeyVerificationStatus status) noexcept { verification_status_ = status; }
    void set_identity_fingerprint(std::string fingerprint) { identity_fingerprint_ = std::move(fingerprint); }
    void set_blocked(bool blocked) noexcept { is_blocked_ = blocked; }
    void set_safety_number(std::string safety_number) { safety_number_ = std::move(safety_number); }
    void set_role_note(std::string role_note) { role_note_ = std::move(role_note); }
    void set_presence_status(PresenceStatus status) noexcept { presence_status_ = status; }
    void set_authorized_device_count(uint32_t count) noexcept { authorized_device_count_ = count; }
    void set_updated_at(std::chrono::system_clock::time_point tp) noexcept { updated_at_ = tp; }

    bool operator==(const Contact& other) const noexcept;
    bool operator!=(const Contact& other) const noexcept { return !(*this == other); }

  private:
    UserId user_id_;
    std::string alias_;
    KeyVerificationStatus verification_status_{KeyVerificationStatus::Unverified};
    std::string identity_fingerprint_;
    bool is_blocked_{false};
    std::string safety_number_;
    std::string role_note_;
    PresenceStatus presence_status_{PresenceStatus::Offline};
    uint32_t authorized_device_count_{1};
    std::chrono::system_clock::time_point updated_at_{std::chrono::system_clock::now()};
};

} // namespace securecloud::client::domain
