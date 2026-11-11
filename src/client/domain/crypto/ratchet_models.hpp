#pragma once

#include "application/client_error.hpp"
#include "domain/crypto/x3dh_models.hpp"
#include "domain/device_id.hpp"
#include "domain/prekey_policy.hpp"
#include "domain/user_id.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace securecloud::client::domain::crypto {

class RatchetHeader {
  public:
    static constexpr uint8_t kMagicByte = 0x52; // 'R'
    static constexpr uint8_t kVersion = 0x01;
    static constexpr std::size_t kSerializedSize = 2 + PrekeyPolicy::kX25519PublicKeySize + 4 + 4; // 42 bytes

    RatchetHeader() = default;
    RatchetHeader(std::vector<uint8_t> dh_pub, uint32_t pn, uint32_t n);

    [[nodiscard]] const std::vector<uint8_t>& dh_pub() const noexcept { return dh_pub_; }
    [[nodiscard]] uint32_t pn() const noexcept { return pn_; }
    [[nodiscard]] uint32_t n() const noexcept { return n_; }

    [[nodiscard]] std::vector<uint8_t> serialize() const;
    static application::ClientResult<RatchetHeader> deserialize(std::span<const uint8_t> bytes);

    bool operator==(const RatchetHeader& other) const noexcept;
    bool operator!=(const RatchetHeader& other) const noexcept { return !(*this == other); }

  private:
    std::vector<uint8_t> dh_pub_;
    uint32_t pn_{0};
    uint32_t n_{0};
};

struct DoubleRatchetMessage {
    RatchetHeader header;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> auth_tag;

    [[nodiscard]] std::vector<uint8_t> serialize() const;
    static application::ClientResult<DoubleRatchetMessage> deserialize(std::span<const uint8_t> bytes);

    bool operator==(const DoubleRatchetMessage& other) const noexcept;
    bool operator!=(const DoubleRatchetMessage& other) const noexcept { return !(*this == other); }
};

struct EncryptedMessageEnvelope {
    static constexpr uint8_t kMagic[3] = {'S', 'C', 'E'};
    static constexpr uint8_t kFormatVersion = 1;

    std::optional<X3dhHeader> x3dh_header;
    DoubleRatchetMessage ratchet_message;

    [[nodiscard]] std::vector<uint8_t> serialize() const;
    static application::ClientResult<EncryptedMessageEnvelope> deserialize(std::span<const uint8_t> bytes);

    bool operator==(const EncryptedMessageEnvelope& other) const noexcept;
    bool operator!=(const EncryptedMessageEnvelope& other) const noexcept { return !(*this == other); }
};

struct PerDeviceDeliveryPayload {
    domain::UserId recipient_user_id;
    domain::DeviceId recipient_device_id;
    std::string ciphertext_blob;
    std::vector<uint8_t> ephemeral_public_key;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> auth_tag;
    std::string algorithm{"AES-256-GCM"};

    bool operator==(const PerDeviceDeliveryPayload& other) const noexcept = default;
};

} // namespace securecloud::client::domain::crypto
