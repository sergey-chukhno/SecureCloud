#pragma once

#include "application/client_error.hpp"
#include "domain/conversation_id.hpp"
#include "domain/device_id.hpp"
#include "domain/user_id.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace securecloud::client::domain::crypto {

struct SenderKeyId {
    domain::ConversationId conversation_id;
    domain::UserId sender_user_id;
    domain::DeviceId sender_device_id;
    uint64_t key_epoch{1};

    [[nodiscard]] std::string storage_key() const;

    bool operator==(const SenderKeyId& other) const noexcept = default;
    bool operator!=(const SenderKeyId& other) const noexcept = default;
};

struct SenderKeyDistributionMessage {
    static constexpr uint8_t kMagic[4] = {'S', 'C', 'K', 'D'};
    static constexpr uint8_t kFormatVersion = 1;

    SenderKeyId id;
    uint32_t iteration{0};
    std::vector<uint8_t> chain_key;
    std::vector<uint8_t> signing_public_key;

    [[nodiscard]] std::vector<uint8_t> serialize() const;
    static application::ClientResult<SenderKeyDistributionMessage> deserialize(std::span<const uint8_t> bytes);

    bool operator==(const SenderKeyDistributionMessage& other) const noexcept = default;
    bool operator!=(const SenderKeyDistributionMessage& other) const noexcept = default;
};

struct GroupEncryptedEnvelope {
    static constexpr uint8_t kMagic[3] = {'S', 'C', 'G'};
    static constexpr uint8_t kFormatVersion = 1;

    SenderKeyId id;
    uint32_t iteration{0};
    std::vector<uint8_t> iv;
    std::vector<uint8_t> auth_tag;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> signature;

    [[nodiscard]] std::vector<uint8_t> canonical_signed_bytes() const;
    [[nodiscard]] std::vector<uint8_t> serialize() const;
    static application::ClientResult<GroupEncryptedEnvelope> deserialize(std::span<const uint8_t> bytes);

    bool operator==(const GroupEncryptedEnvelope& other) const noexcept = default;
    bool operator!=(const GroupEncryptedEnvelope& other) const noexcept = default;
};

struct SenderKeyState {
    static constexpr uint8_t kMagic[4] = {'S', 'C', 'S', 'K'};
    static constexpr uint8_t kFormatVersion = 1;

    SenderKeyId id;
    uint32_t iteration{0};
    common::configuration::SecretString chain_key;
    std::vector<uint8_t> signing_public_key;
    std::optional<common::configuration::SecretString> signing_private_key;
    std::map<uint32_t, common::configuration::SecretString> skipped_message_keys;

    [[nodiscard]] std::vector<uint8_t> serialize() const;
    static application::ClientResult<SenderKeyState> deserialize(std::span<const uint8_t> bytes);

    bool operator==(const SenderKeyState& other) const noexcept = default;
    bool operator!=(const SenderKeyState& other) const noexcept = default;
};

} // namespace securecloud::client::domain::crypto
