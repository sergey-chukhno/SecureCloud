#include "application/managers/ratchet_session_manager.hpp"

#include "domain/crypto/double_ratchet_engine.hpp"
#include "domain/crypto/x3dh_engine.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"

#include <sstream>

namespace securecloud::client::application::managers {

RatchetSessionManager::RatchetSessionManager(interfaces::IGatewayClient& gateway,
                                             interfaces::ISecureStorage& secure_storage,
                                             interfaces::ICryptoProvider& crypto_provider, domain::UserId local_user_id,
                                             domain::DeviceId local_device_id)
    : gateway_(gateway), secure_storage_(secure_storage), crypto_provider_(crypto_provider),
      local_user_id_(std::move(local_user_id)), local_device_id_(std::move(local_device_id)) {}

std::string RatchetSessionManager::make_storage_key(const domain::UserId& peer_user_id,
                                                    const domain::DeviceId& peer_device_id) {
    return std::string(kSessionKeyPrefix) + std::string(peer_user_id.str()) + ":" + std::string(peer_device_id.str());
}

ClientResult<void> RatchetSessionManager::ensure_outbound_session(const domain::UserId& peer_user_id,
                                                                  const domain::DeviceId& peer_device_id) {
    domain::crypto::PeerDeviceKey key{.user_id = peer_user_id, .device_id = peer_device_id};
    if (sessions_.contains(key)) {
        return ClientResult<void>::ok();
    }

    // Try restoring from secure storage first
    auto load_res = load_session(peer_user_id, peer_device_id);
    if (load_res.is_ok()) {
        return ClientResult<void>::ok();
    }

    // Otherwise establish new X3DH session via Gateway directory
    auto dir_res = gateway_.get_device_crypto_directory(peer_user_id, {peer_device_id});
    if (!dir_res.is_ok()) {
        return ClientResult<void>::error(dir_res.error());
    }

    const auto& entries = dir_res.value();
    auto it = std::find_if(
        entries.begin(), entries.end(),
        [&peer_device_id](const interfaces::DeviceCryptoDirectoryEntry& e) { return e.device_id == peer_device_id; });
    if (it == entries.end()) {
        return ClientResult<void>::error(
            ClientError::crypto("Target device not found in directory: " + std::string(peer_device_id.str())));
    }

    const auto& entry = *it;
    if (entry.status != domain::DeviceAuthorizationStatus::Authorized) {
        return ClientResult<void>::error(
            ClientError::crypto("Target device is revoked or unauthorized: " + std::string(peer_device_id.str())));
    }

    auto bundle_res = infrastructure::adapters::KeyStorageHelper::load_bundle(secure_storage_, local_device_id_);
    if (!bundle_res.is_ok()) {
        return ClientResult<void>::error(
            ClientError::crypto("Failed to load local device private bundle: " + bundle_res.error().user_message()));
    }
    const auto& bundle = bundle_res.value();

    auto x3dh_res = domain::crypto::X3dhEngine::initiate_handshake(crypto_provider_, bundle, entry);
    if (!x3dh_res.is_ok()) {
        return ClientResult<void>::error(x3dh_res.error());
    }

    auto dr_res = domain::crypto::DoubleRatchetEngine::initialize_alice(
        crypto_provider_, x3dh_res.value().shared_secret, entry.signed_prekey);
    if (!dr_res.is_ok()) {
        return ClientResult<void>::error(dr_res.error());
    }

    domain::crypto::RatchetSession new_session{
        .peer_user_id = peer_user_id,
        .peer_device_id = peer_device_id,
        .peer_identity_key = entry.identity_key,
        .ratchet_state = std::move(dr_res).value(),
        .initial_message_pending = true,
        .pending_x3dh_header = std::move(x3dh_res.value().header),
        .established_at = std::chrono::system_clock::now(),
        .last_active_at = std::chrono::system_clock::now(),
    };

    sessions_.emplace(key, std::move(new_session));
    return save_session(peer_user_id, peer_device_id);
}

ClientResult<domain::crypto::EncryptedMessageEnvelope>
RatchetSessionManager::encrypt_for_device(const domain::UserId& peer_user_id, const domain::DeviceId& peer_device_id,
                                          std::span<const uint8_t> plaintext) {
    auto ens_res = ensure_outbound_session(peer_user_id, peer_device_id);
    if (!ens_res.is_ok()) {
        return ClientResult<domain::crypto::EncryptedMessageEnvelope>::error(ens_res.error());
    }

    domain::crypto::PeerDeviceKey key{.user_id = peer_user_id, .device_id = peer_device_id};
    auto it = sessions_.find(key);
    if (it == sessions_.end()) {
        return ClientResult<domain::crypto::EncryptedMessageEnvelope>::error(
            ClientError::crypto("Session state missing after initialization"));
    }

    auto& session = it->second;
    auto enc_res =
        domain::crypto::DoubleRatchetEngine::ratchet_encrypt(crypto_provider_, session.ratchet_state, plaintext);
    if (!enc_res.is_ok()) {
        return ClientResult<domain::crypto::EncryptedMessageEnvelope>::error(enc_res.error());
    }

    domain::crypto::EncryptedMessageEnvelope envelope{
        .x3dh_header = session.initial_message_pending ? session.pending_x3dh_header : std::nullopt,
        .ratchet_message = std::move(enc_res).value(),
    };

    session.initial_message_pending = false;
    session.pending_x3dh_header = std::nullopt;
    session.last_active_at = std::chrono::system_clock::now();

    auto save_res = save_session(peer_user_id, peer_device_id);
    if (!save_res.is_ok()) {
        return ClientResult<domain::crypto::EncryptedMessageEnvelope>::error(save_res.error());
    }

    return ClientResult<domain::crypto::EncryptedMessageEnvelope>::ok(std::move(envelope));
}

ClientResult<domain::crypto::PerDeviceDeliveryPayload> RatchetSessionManager::encrypt_payload_for_device(
    const domain::UserId& peer_user_id, const domain::DeviceId& peer_device_id, std::span<const uint8_t> plaintext) {
    auto env_res = encrypt_for_device(peer_user_id, peer_device_id, plaintext);
    if (!env_res.is_ok()) {
        return ClientResult<domain::crypto::PerDeviceDeliveryPayload>::error(env_res.error());
    }

    const auto& env = env_res.value();
    auto bytes = env.serialize();
    std::string blob(reinterpret_cast<const char*>(bytes.data()), bytes.size());

    domain::crypto::PerDeviceDeliveryPayload payload{
        .recipient_user_id = peer_user_id,
        .recipient_device_id = peer_device_id,
        .ciphertext_blob = std::move(blob),
        .ephemeral_public_key = env.ratchet_message.header.dh_pub(),
        .iv = env.ratchet_message.iv,
        .auth_tag = env.ratchet_message.auth_tag,
        .algorithm = "AES-256-GCM",
    };

    return ClientResult<domain::crypto::PerDeviceDeliveryPayload>::ok(std::move(payload));
}

ClientResult<std::vector<domain::crypto::PerDeviceDeliveryPayload>>
RatchetSessionManager::encrypt_fanout(const std::vector<std::pair<domain::UserId, domain::DeviceId>>& targets,
                                      std::span<const uint8_t> plaintext) {
    if (targets.empty()) {
        return ClientResult<std::vector<domain::crypto::PerDeviceDeliveryPayload>>::error(
            ClientError::validation("Target device list cannot be empty for fanout encryption"));
    }

    std::vector<domain::crypto::PerDeviceDeliveryPayload> results;
    results.reserve(targets.size());

    for (const auto& [uid, did] : targets) {
        auto p_res = encrypt_payload_for_device(uid, did, plaintext);
        if (!p_res.is_ok()) {
            return ClientResult<std::vector<domain::crypto::PerDeviceDeliveryPayload>>::error(p_res.error());
        }
        results.push_back(std::move(p_res).value());
    }

    return ClientResult<std::vector<domain::crypto::PerDeviceDeliveryPayload>>::ok(std::move(results));
}

ClientResult<std::vector<domain::crypto::PerDeviceDeliveryPayload>>
RatchetSessionManager::encrypt_fanout_for_participants(const std::vector<domain::UserId>& participants,
                                                       std::span<const uint8_t> plaintext) {
    std::vector<std::pair<domain::UserId, domain::DeviceId>> targets;

    for (const auto& uid : participants) {
        auto dir_res = gateway_.get_device_crypto_directory(uid, {});
        if (!dir_res.is_ok()) {
            return ClientResult<std::vector<domain::crypto::PerDeviceDeliveryPayload>>::error(dir_res.error());
        }

        for (const auto& entry : dir_res.value()) {
            if (entry.status != domain::DeviceAuthorizationStatus::Authorized) {
                continue;
            }
            if (uid == local_user_id_ && entry.device_id == local_device_id_) {
                continue; // Do not loopback to this exact physical sender device
            }
            targets.emplace_back(uid, entry.device_id);
        }
    }

    return encrypt_fanout(targets, plaintext);
}

ClientResult<securecloud::common::configuration::SecretString>
RatchetSessionManager::decrypt_from_device(const domain::UserId& sender_user_id,
                                           const domain::DeviceId& sender_device_id,
                                           const domain::crypto::EncryptedMessageEnvelope& envelope) {
    domain::crypto::PeerDeviceKey key{.user_id = sender_user_id, .device_id = sender_device_id};

    auto it = sessions_.find(key);
    if (it == sessions_.end()) {
        auto load_res = load_session(sender_user_id, sender_device_id);
        if (load_res.is_ok()) {
            it = sessions_.find(key);
        }
    }

    if (it == sessions_.end()) {
        // Initial inbound message: requires X3DH header
        if (!envelope.x3dh_header.has_value()) {
            return ClientResult<securecloud::common::configuration::SecretString>::error(
                ClientError::crypto("Cannot decrypt inbound message: no existing session and missing X3DH header"));
        }

        auto bundle_res = infrastructure::adapters::KeyStorageHelper::load_bundle(secure_storage_, local_device_id_);
        if (!bundle_res.is_ok()) {
            return ClientResult<securecloud::common::configuration::SecretString>::error(ClientError::crypto(
                "Failed to load local device private bundle: " + bundle_res.error().user_message()));
        }
        auto bundle = bundle_res.value();

        auto resp_res = domain::crypto::X3dhEngine::process_handshake(crypto_provider_, bundle, *envelope.x3dh_header);
        if (!resp_res.is_ok()) {
            return ClientResult<securecloud::common::configuration::SecretString>::error(resp_res.error());
        }

        if (resp_res.value().claimed_one_time_prekey_id.has_value()) {
            auto purge_res = infrastructure::adapters::KeyStorageHelper::remove_one_time_prekey(
                secure_storage_, local_device_id_, *resp_res.value().claimed_one_time_prekey_id);
            if (!purge_res.is_ok()) {
                return ClientResult<securecloud::common::configuration::SecretString>::error(purge_res.error());
            }
        }

        application::interfaces::DhKeyPair bob_dh_pair{
            .public_key = bundle.signed_prekey_public_key(),
            .private_key = bundle.signed_prekey_private_key(),
        };

        auto dr_res = domain::crypto::DoubleRatchetEngine::initialize_bob(
            crypto_provider_, resp_res.value().shared_secret, std::move(bob_dh_pair));
        if (!dr_res.is_ok()) {
            return ClientResult<securecloud::common::configuration::SecretString>::error(dr_res.error());
        }

        domain::crypto::RatchetSession new_session{
            .peer_user_id = sender_user_id,
            .peer_device_id = sender_device_id,
            .peer_identity_key = envelope.x3dh_header->initiator_identity_key(),
            .ratchet_state = std::move(dr_res).value(),
            .initial_message_pending = false,
            .pending_x3dh_header = std::nullopt,
            .established_at = std::chrono::system_clock::now(),
            .last_active_at = std::chrono::system_clock::now(),
        };

        it = sessions_.emplace(key, std::move(new_session)).first;
    }

    auto& session = it->second;
    auto dec_res = domain::crypto::DoubleRatchetEngine::ratchet_decrypt(crypto_provider_, session.ratchet_state,
                                                                        envelope.ratchet_message);
    if (!dec_res.is_ok()) {
        return dec_res;
    }

    session.last_active_at = std::chrono::system_clock::now();
    auto save_res = save_session(sender_user_id, sender_device_id);
    if (!save_res.is_ok()) {
        return ClientResult<securecloud::common::configuration::SecretString>::error(save_res.error());
    }

    return dec_res;
}

ClientResult<securecloud::common::configuration::SecretString>
RatchetSessionManager::decrypt_payload_from_device(const domain::UserId& sender_user_id,
                                                   const domain::DeviceId& sender_device_id,
                                                   const domain::crypto::PerDeviceDeliveryPayload& payload) {
    std::span<const uint8_t> bytes(reinterpret_cast<const uint8_t*>(payload.ciphertext_blob.data()),
                                   payload.ciphertext_blob.size());
    auto env_res = domain::crypto::EncryptedMessageEnvelope::deserialize(bytes);
    if (!env_res.is_ok()) {
        return ClientResult<securecloud::common::configuration::SecretString>::error(env_res.error());
    }

    return decrypt_from_device(sender_user_id, sender_device_id, env_res.value());
}

ClientResult<void> RatchetSessionManager::save_session(const domain::UserId& peer_user_id,
                                                       const domain::DeviceId& peer_device_id) {
    domain::crypto::PeerDeviceKey key{.user_id = peer_user_id, .device_id = peer_device_id};
    auto it = sessions_.find(key);
    if (it == sessions_.end()) {
        return ClientResult<void>::error(ClientError::crypto("Session not found for saving"));
    }

    auto ser_res = domain::crypto::RatchetSessionSerializer::serialize(it->second);
    if (!ser_res.is_ok()) {
        return ClientResult<void>::error(ser_res.error());
    }

    const auto storage_key = make_storage_key(peer_user_id, peer_device_id);
    auto store_res = secure_storage_.store_secret(storage_key, ser_res.value());
    if (!store_res.is_ok()) {
        return ClientResult<void>::error(store_res.error());
    }

    return persist_session_index();
}

ClientResult<void> RatchetSessionManager::load_session(const domain::UserId& peer_user_id,
                                                       const domain::DeviceId& peer_device_id) {
    const auto storage_key = make_storage_key(peer_user_id, peer_device_id);
    auto get_res = secure_storage_.get_secret(storage_key);
    if (!get_res.is_ok()) {
        return ClientResult<void>::error(get_res.error());
    }

    auto deser_res = domain::crypto::RatchetSessionSerializer::deserialize(get_res.value());
    if (!deser_res.is_ok()) {
        return ClientResult<void>::error(deser_res.error());
    }

    domain::crypto::PeerDeviceKey key{.user_id = peer_user_id, .device_id = peer_device_id};
    sessions_[key] = std::move(deser_res).value();
    return ClientResult<void>::ok();
}

ClientResult<void> RatchetSessionManager::persist_session_index() {
    std::ostringstream ss;
    for (const auto& [k, _] : sessions_) {
        ss << k.user_id.str() << ":" << k.device_id.str() << "\n";
    }
    return secure_storage_.store_secret(kSessionIndexKey, securecloud::common::configuration::SecretString(ss.str()));
}

ClientResult<void> RatchetSessionManager::load_all_sessions() {
    auto idx_res = secure_storage_.get_secret(kSessionIndexKey);
    if (!idx_res.is_ok()) {
        return ClientResult<void>::ok(); // No index yet, fresh start
    }

    const auto& idx_str = idx_res.value().expose_unredacted_secret();
    std::istringstream stream(idx_str);
    std::string line;

    while (std::getline(stream, line)) {
        if (line.empty()) {
            continue;
        }
        auto colon = line.find(':');
        if (colon == std::string::npos) {
            continue;
        }
        domain::UserId uid(line.substr(0, colon));
        domain::DeviceId did(line.substr(colon + 1));
        load_session(uid, did);
    }

    return ClientResult<void>::ok();
}

ClientResult<void> RatchetSessionManager::terminate_session(const domain::UserId& peer_user_id,
                                                            const domain::DeviceId& peer_device_id) {
    domain::crypto::PeerDeviceKey key{.user_id = peer_user_id, .device_id = peer_device_id};
    sessions_.erase(key);

    const auto storage_key = make_storage_key(peer_user_id, peer_device_id);
    secure_storage_.delete_secret(storage_key);
    return persist_session_index();
}

ClientResult<void> RatchetSessionManager::purge_device_sessions(const domain::DeviceId& device_id) {
    if (device_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Device ID cannot be empty to purge sessions"));
    }

    std::vector<domain::UserId> matched_users;
    for (const auto& [k, _] : sessions_) {
        if (k.device_id == device_id) {
            matched_users.push_back(k.user_id);
        }
    }

    for (const auto& uid : matched_users) {
        auto res = terminate_session(uid, device_id);
        if (!res.is_ok()) {
            return res;
        }
    }

    return ClientResult<void>::ok();
}

bool RatchetSessionManager::has_session(const domain::UserId& peer_user_id,
                                        const domain::DeviceId& peer_device_id) const {
    domain::crypto::PeerDeviceKey key{.user_id = peer_user_id, .device_id = peer_device_id};
    return sessions_.contains(key);
}

std::optional<std::vector<uint8_t>>
RatchetSessionManager::get_peer_identity_key(const domain::UserId& peer_user_id,
                                             const domain::DeviceId& peer_device_id) const {
    domain::crypto::PeerDeviceKey key{.user_id = peer_user_id, .device_id = peer_device_id};
    auto it = sessions_.find(key);
    if (it != sessions_.end()) {
        return it->second.peer_identity_key;
    }
    return std::nullopt;
}

std::size_t RatchetSessionManager::active_session_count() const noexcept {
    return sessions_.size();
}

} // namespace securecloud::client::application::managers
