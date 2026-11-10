#pragma once

#include "application/client_error.hpp"
#include "domain/device_id.hpp"
#include "domain/prekey_policy.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::domain::crypto {

class X3dhHeader {
  public:
    static constexpr uint8_t kMagicByte = 0x53; // 'S'
    static constexpr uint8_t kVersion = 0x01;

    X3dhHeader() = default;

    X3dhHeader(DeviceId initiator_device_id, std::vector<uint8_t> initiator_identity_key,
               std::vector<uint8_t> initiator_ephemeral_key, std::vector<uint8_t> initiator_dh_key,
               std::optional<std::string> one_time_prekey_id = std::nullopt);

    [[nodiscard]] const DeviceId& initiator_device_id() const noexcept { return initiator_device_id_; }
    [[nodiscard]] const std::vector<uint8_t>& initiator_identity_key() const noexcept {
        return initiator_identity_key_;
    }
    [[nodiscard]] const std::vector<uint8_t>& initiator_ephemeral_key() const noexcept {
        return initiator_ephemeral_key_;
    }
    [[nodiscard]] const std::vector<uint8_t>& initiator_dh_key() const noexcept { return initiator_dh_key_; }
    [[nodiscard]] const std::optional<std::string>& one_time_prekey_id() const noexcept { return one_time_prekey_id_; }
    [[nodiscard]] bool has_one_time_prekey() const noexcept { return one_time_prekey_id_.has_value(); }

    [[nodiscard]] std::vector<uint8_t> serialize() const;
    static application::ClientResult<X3dhHeader> deserialize(std::span<const uint8_t> bytes);

    bool operator==(const X3dhHeader& other) const noexcept;
    bool operator!=(const X3dhHeader& other) const noexcept { return !(*this == other); }

  private:
    DeviceId initiator_device_id_;
    std::vector<uint8_t> initiator_identity_key_;
    std::vector<uint8_t> initiator_ephemeral_key_;
    std::vector<uint8_t> initiator_dh_key_;
    std::optional<std::string> one_time_prekey_id_;
};

struct X3dhInitiatorResult {
    securecloud::common::configuration::SecretString shared_secret;
    X3dhHeader header;
};

struct X3dhResponderResult {
    securecloud::common::configuration::SecretString shared_secret;
    std::optional<std::string> claimed_one_time_prekey_id;
};

} // namespace securecloud::client::domain::crypto

