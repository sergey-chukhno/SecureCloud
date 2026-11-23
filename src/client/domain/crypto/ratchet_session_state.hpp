#pragma once

#include "application/client_error.hpp"
#include "domain/crypto/ratchet_models.hpp"
#include "domain/crypto/ratchet_state.hpp"
#include "domain/crypto/x3dh_models.hpp"
#include "domain/device_id.hpp"
#include "domain/user_id.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace securecloud::client::domain::crypto {

struct PeerDeviceKey {
    domain::UserId user_id;
    domain::DeviceId device_id;

    bool operator==(const PeerDeviceKey& other) const noexcept {
        return user_id == other.user_id && device_id == other.device_id;
    }
};

struct PeerDeviceKeyHash {
    std::size_t operator()(const PeerDeviceKey& k) const noexcept {
        return std::hash<std::string_view>{}(k.user_id.str()) ^ (std::hash<std::string_view>{}(k.device_id.str()) << 1);
    }
};

struct RatchetSession {
    domain::UserId peer_user_id;
    domain::DeviceId peer_device_id;
    std::vector<uint8_t> peer_identity_key;
    RatchetState ratchet_state;
    bool initial_message_pending{false};
    std::optional<X3dhHeader> pending_x3dh_header;
    std::chrono::system_clock::time_point established_at{std::chrono::system_clock::now()};
    std::chrono::system_clock::time_point last_active_at{std::chrono::system_clock::now()};
};

class RatchetSessionSerializer {
  public:
    static application::ClientResult<securecloud::common::configuration::SecretString>
    serialize(const RatchetSession& session);

    static application::ClientResult<RatchetSession>
    deserialize(const securecloud::common::configuration::SecretString& data);
};

} // namespace securecloud::client::domain::crypto
