#pragma once

#include "domain/device_id.hpp"
#include "domain/prekey_bundle.hpp"
#include "domain/prekey_policy.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace securecloud::client::domain {

class DevicePrivateBundle {
  public:
    DevicePrivateBundle() = default;

    DevicePrivateBundle(
        DeviceId device_id, std::vector<uint8_t> identity_public_key,
        securecloud::common::configuration::SecretString identity_private_key,
        std::vector<uint8_t> signed_prekey_public_key,
        securecloud::common::configuration::SecretString signed_prekey_private_key,
        std::vector<uint8_t> signed_prekey_signature,
        std::unordered_map<std::string, securecloud::common::configuration::SecretString> one_time_prekey_privates = {},
        std::chrono::system_clock::time_point created_at = std::chrono::system_clock::now());

    [[nodiscard]] const DeviceId& device_id() const noexcept { return device_id_; }
    [[nodiscard]] const std::vector<uint8_t>& identity_public_key() const noexcept { return identity_public_key_; }
    [[nodiscard]] const securecloud::common::configuration::SecretString& identity_private_key() const noexcept {
        return identity_private_key_;
    }
    [[nodiscard]] const std::vector<uint8_t>& signed_prekey_public_key() const noexcept {
        return signed_prekey_public_key_;
    }
    [[nodiscard]] const securecloud::common::configuration::SecretString& signed_prekey_private_key() const noexcept {
        return signed_prekey_private_key_;
    }
    [[nodiscard]] const std::vector<uint8_t>& signed_prekey_signature() const noexcept {
        return signed_prekey_signature_;
    }
    [[nodiscard]] const std::unordered_map<std::string, securecloud::common::configuration::SecretString>&
    one_time_prekey_privates() const noexcept {
        return one_time_prekey_privates_;
    }
    [[nodiscard]] std::size_t one_time_prekey_count() const noexcept { return one_time_prekey_privates_.size(); }
    [[nodiscard]] bool has_one_time_prekey(std::string_view prekey_id) const noexcept;
    [[nodiscard]] std::chrono::system_clock::time_point created_at() const noexcept { return created_at_; }

    std::optional<securecloud::common::configuration::SecretString> take_one_time_prekey(std::string_view prekey_id);

    void add_one_time_prekey(std::string prekey_id, securecloud::common::configuration::SecretString private_key);

    void update_signed_prekey(std::vector<uint8_t> new_public_key,
                              securecloud::common::configuration::SecretString new_private_key,
                              std::vector<uint8_t> new_signature);

    [[nodiscard]] PrekeyBundle to_public_bundle(const std::vector<OneTimePrekeyRecord>& otpk_public_records = {}) const;

    bool operator==(const DevicePrivateBundle& other) const noexcept;
    bool operator!=(const DevicePrivateBundle& other) const noexcept { return !(*this == other); }

  private:
    DeviceId device_id_;
    std::vector<uint8_t> identity_public_key_;
    securecloud::common::configuration::SecretString identity_private_key_;
    std::vector<uint8_t> signed_prekey_public_key_;
    securecloud::common::configuration::SecretString signed_prekey_private_key_;
    std::vector<uint8_t> signed_prekey_signature_;
    std::unordered_map<std::string, securecloud::common::configuration::SecretString> one_time_prekey_privates_;
    std::chrono::system_clock::time_point created_at_{std::chrono::system_clock::now()};
};

} // namespace securecloud::client::domain
