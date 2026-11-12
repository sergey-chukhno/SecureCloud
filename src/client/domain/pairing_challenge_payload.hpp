#pragma once

#include "application/client_error.hpp"
#include "domain/device_id.hpp"
#include "domain/user_id.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::domain {

class PairingChallengePayload {
  public:
    static constexpr std::string_view kUriScheme = "securecloud://pair";
    static constexpr uint32_t kCurrentVersion = 1;

    PairingChallengePayload() = default;

    PairingChallengePayload(UserId user_id, DeviceId device_id, std::vector<uint8_t> ephemeral_public_key,
                            std::string pairing_code, std::chrono::system_clock::time_point expires_at,
                            std::string display_name = "", uint32_t version = kCurrentVersion);

    [[nodiscard]] uint32_t version() const noexcept { return version_; }
    [[nodiscard]] const UserId& user_id() const noexcept { return user_id_; }
    [[nodiscard]] const DeviceId& device_id() const noexcept { return device_id_; }
    [[nodiscard]] const std::vector<uint8_t>& ephemeral_public_key() const noexcept { return ephemeral_public_key_; }
    [[nodiscard]] const std::string& pairing_code() const noexcept { return pairing_code_; }
    [[nodiscard]] std::chrono::system_clock::time_point expires_at() const noexcept { return expires_at_; }
    [[nodiscard]] const std::string& display_name() const noexcept { return display_name_; }

    void set_version(uint32_t v) noexcept { version_ = v; }
    void set_user_id(UserId uid) { user_id_ = std::move(uid); }
    void set_device_id(DeviceId did) { device_id_ = std::move(did); }
    void set_ephemeral_public_key(std::vector<uint8_t> pk) { ephemeral_public_key_ = std::move(pk); }
    void set_pairing_code(std::string code) { pairing_code_ = std::move(code); }
    void set_expires_at(std::chrono::system_clock::time_point exp) noexcept { expires_at_ = exp; }
    void set_display_name(std::string name) { display_name_ = std::move(name); }

    [[nodiscard]] bool
    is_expired(std::chrono::system_clock::time_point now = std::chrono::system_clock::now()) const noexcept;

    [[nodiscard]] std::string to_uri() const;
    static application::ClientResult<PairingChallengePayload> from_uri(std::string_view uri_str);

    bool operator==(const PairingChallengePayload& other) const noexcept;
    bool operator!=(const PairingChallengePayload& other) const noexcept { return !(*this == other); }

  private:
    uint32_t version_{kCurrentVersion};
    UserId user_id_;
    DeviceId device_id_;
    std::vector<uint8_t> ephemeral_public_key_;
    std::string pairing_code_;
    std::chrono::system_clock::time_point expires_at_{};
    std::string display_name_;
};

} // namespace securecloud::client::domain
