#pragma once

#include "application/client_error.hpp"
#include "domain/prekey_policy.hpp"

#include <cstdint>
#include <span>
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

} // namespace securecloud::client::domain::crypto

