#include "domain/crypto/x3dh_engine.hpp"

#include <openssl/crypto.h>

namespace securecloud::client::domain::crypto {

namespace {

application::ClientResult<securecloud::common::configuration::SecretString>
derive_x3dh_master_secret(application::interfaces::ICryptoProvider& crypto,
                          const securecloud::common::configuration::SecretString& dh1,
                          const securecloud::common::configuration::SecretString& dh2,
                          const securecloud::common::configuration::SecretString& dh3,
                          const std::optional<securecloud::common::configuration::SecretString>& dh4_opt) {
    std::string ikm_raw;
    const std::size_t total_len = dh1.size() + dh2.size() + dh3.size() + (dh4_opt.has_value() ? dh4_opt->size() : 0);
    ikm_raw.reserve(total_len);

    ikm_raw.append(dh1.expose_unredacted_secret());
    ikm_raw.append(dh2.expose_unredacted_secret());
    ikm_raw.append(dh3.expose_unredacted_secret());
    if (dh4_opt.has_value()) {
        ikm_raw.append(dh4_opt->expose_unredacted_secret());
    }

    securecloud::common::configuration::SecretString ikm(std::move(ikm_raw));

    const std::vector<uint8_t> salt(32, 0x00);
    const std::string_view info = X3dhEngine::kX3dhInfoLabel;
    std::span<const uint8_t> info_span(reinterpret_cast<const uint8_t*>(info.data()), info.size());

    return crypto.hkdf_extract_and_expand(salt, ikm, info_span, PrekeyPolicy::kSharedSecretSize);
}

} // namespace

application::ClientResult<X3dhInitiatorResult>
X3dhEngine::initiate_handshake(application::interfaces::ICryptoProvider& crypto,
                               const domain::DevicePrivateBundle& local_bundle,
                               const application::interfaces::DeviceCryptoDirectoryEntry& peer_bundle) {
    // 1. Verify peer signed prekey signature
    auto verify_res = crypto.verify_signed_prekey(peer_bundle.identity_key, peer_bundle.signed_prekey,
                                                  peer_bundle.signed_prekey_signature);
    if (!verify_res.is_ok() || !verify_res.value()) {
        return application::ClientResult<X3dhInitiatorResult>::error(
            application::ClientError::crypto("Invalid signed prekey signature in peer directory bundle"));
    }

    // 2. Generate fresh ephemeral keypair
    auto eph_res = crypto.generate_dh_keypair();
    if (!eph_res.is_ok()) {
        return application::ClientResult<X3dhInitiatorResult>::error(eph_res.error());
    }
    auto eph_pair = std::move(eph_res).value();

    // 3. Perform Diffie-Hellman calculations
    auto dh1_res = crypto.diffie_hellman(local_bundle.signed_prekey_private_key(), peer_bundle.signed_prekey);
    if (!dh1_res.is_ok()) {
        return application::ClientResult<X3dhInitiatorResult>::error(dh1_res.error());
    }

    auto dh2_res = crypto.diffie_hellman(eph_pair.private_key, peer_bundle.signed_prekey);
    if (!dh2_res.is_ok()) {
        return application::ClientResult<X3dhInitiatorResult>::error(dh2_res.error());
    }

    auto dh3_res = crypto.diffie_hellman(eph_pair.private_key, peer_bundle.signed_prekey);
    if (!dh3_res.is_ok()) {
        return application::ClientResult<X3dhInitiatorResult>::error(dh3_res.error());
    }

    std::optional<securecloud::common::configuration::SecretString> dh4_opt;
    std::optional<std::string> otpk_id_opt;

    if (peer_bundle.one_time_prekey.has_value() && !peer_bundle.one_time_prekey->empty()) {
        auto dh4_res = crypto.diffie_hellman(eph_pair.private_key, *peer_bundle.one_time_prekey);
        if (!dh4_res.is_ok()) {
            return application::ClientResult<X3dhInitiatorResult>::error(dh4_res.error());
        }
        dh4_opt = std::move(dh4_res).value();
        otpk_id_opt = peer_bundle.one_time_prekey_id;
    }

    // 4. Derive Master Shared Key
    auto sk_res = derive_x3dh_master_secret(crypto, dh1_res.value(), dh2_res.value(), dh3_res.value(), dh4_opt);
    if (!sk_res.is_ok()) {
        return application::ClientResult<X3dhInitiatorResult>::error(sk_res.error());
    }

    // 5. Construct initial X3dhHeader
    X3dhHeader header(local_bundle.device_id(), local_bundle.identity_public_key(), std::move(eph_pair.public_key),
                      local_bundle.signed_prekey_public_key(), std::move(otpk_id_opt));

    return application::ClientResult<X3dhInitiatorResult>::ok(
        X3dhInitiatorResult{.shared_secret = std::move(sk_res).value(), .header = std::move(header)});
}

application::ClientResult<X3dhInitiatorResult>
X3dhEngine::initiate_handshake(application::interfaces::ICryptoProvider& crypto,
                               const domain::DevicePrivateBundle& local_bundle, const domain::PrekeyBundle& peer_bundle,
                               std::optional<std::string> chosen_otpk_id) {
    // 1. Verify peer signed prekey signature
    auto verify_res = crypto.verify_signed_prekey(peer_bundle.identity_key(), peer_bundle.signed_prekey(),
                                                  peer_bundle.signed_prekey_signature());
    if (!verify_res.is_ok() || !verify_res.value()) {
        return application::ClientResult<X3dhInitiatorResult>::error(
            application::ClientError::crypto("Invalid signed prekey signature in peer prekey bundle"));
    }

    // 2. Generate fresh ephemeral keypair
    auto eph_res = crypto.generate_dh_keypair();
    if (!eph_res.is_ok()) {
        return application::ClientResult<X3dhInitiatorResult>::error(eph_res.error());
    }
    auto eph_pair = std::move(eph_res).value();

    // 3. Perform Diffie-Hellman calculations
    auto dh1_res = crypto.diffie_hellman(local_bundle.signed_prekey_private_key(), peer_bundle.signed_prekey());
    if (!dh1_res.is_ok()) {
        return application::ClientResult<X3dhInitiatorResult>::error(dh1_res.error());
    }

    auto dh2_res = crypto.diffie_hellman(eph_pair.private_key, peer_bundle.signed_prekey());
    if (!dh2_res.is_ok()) {
        return application::ClientResult<X3dhInitiatorResult>::error(dh2_res.error());
    }

    auto dh3_res = crypto.diffie_hellman(eph_pair.private_key, peer_bundle.signed_prekey());
    if (!dh3_res.is_ok()) {
        return application::ClientResult<X3dhInitiatorResult>::error(dh3_res.error());
    }

    std::optional<securecloud::common::configuration::SecretString> dh4_opt;
    std::optional<std::string> otpk_id_opt;

    if (!peer_bundle.one_time_prekeys().empty()) {
        const domain::OneTimePrekeyRecord* target_otpk = nullptr;
        if (chosen_otpk_id.has_value()) {
            for (const auto& otk : peer_bundle.one_time_prekeys()) {
                if (otk.id() == *chosen_otpk_id) {
                    target_otpk = &otk;
                    break;
                }
            }
        } else {
            target_otpk = &peer_bundle.one_time_prekeys().front();
        }

        if (target_otpk) {
            auto dh4_res = crypto.diffie_hellman(eph_pair.private_key, target_otpk->public_key());
            if (!dh4_res.is_ok()) {
                return application::ClientResult<X3dhInitiatorResult>::error(dh4_res.error());
            }
            dh4_opt = std::move(dh4_res).value();
            otpk_id_opt = target_otpk->id();
        }
    }

    // 4. Derive Master Shared Key
    auto sk_res = derive_x3dh_master_secret(crypto, dh1_res.value(), dh2_res.value(), dh3_res.value(), dh4_opt);
    if (!sk_res.is_ok()) {
        return application::ClientResult<X3dhInitiatorResult>::error(sk_res.error());
    }

    // 5. Construct initial X3dhHeader
    X3dhHeader header(local_bundle.device_id(), local_bundle.identity_public_key(), std::move(eph_pair.public_key),
                      local_bundle.signed_prekey_public_key(), std::move(otpk_id_opt));

    return application::ClientResult<X3dhInitiatorResult>::ok(
        X3dhInitiatorResult{.shared_secret = std::move(sk_res).value(), .header = std::move(header)});
}

application::ClientResult<X3dhResponderResult>
X3dhEngine::process_handshake(application::interfaces::ICryptoProvider& crypto,
                              domain::DevicePrivateBundle& local_bundle, const X3dhHeader& header) {
    if (header.initiator_ephemeral_key().size() != PrekeyPolicy::kX25519PublicKeySize ||
        header.initiator_dh_key().size() != PrekeyPolicy::kX25519PublicKeySize) {
        return application::ClientResult<X3dhResponderResult>::error(
            application::ClientError::validation("Invalid key lengths in X3dhHeader"));
    }

    // 1. If OTPK was claimed, take and remove the single-use private key
    std::optional<securecloud::common::configuration::SecretString> otpk_priv_opt;
    std::optional<std::string> claimed_otpk_id;

    if (header.has_one_time_prekey()) {
        const auto& otpk_id = *header.one_time_prekey_id();
        auto taken_opt = local_bundle.take_one_time_prekey(otpk_id);
        if (!taken_opt.has_value()) {
            return application::ClientResult<X3dhResponderResult>::error(
                application::ClientError::crypto("One-time prekey not found or already consumed: " + otpk_id));
        }
        otpk_priv_opt = std::move(taken_opt);
        claimed_otpk_id = otpk_id;
    }

    // 2. Compute matching Diffie-Hellman operations
    auto dh1_res = crypto.diffie_hellman(local_bundle.signed_prekey_private_key(), header.initiator_dh_key());
    if (!dh1_res.is_ok()) {
        return application::ClientResult<X3dhResponderResult>::error(dh1_res.error());
    }

    auto dh2_res = crypto.diffie_hellman(local_bundle.signed_prekey_private_key(), header.initiator_ephemeral_key());
    if (!dh2_res.is_ok()) {
        return application::ClientResult<X3dhResponderResult>::error(dh2_res.error());
    }

    auto dh3_res = crypto.diffie_hellman(local_bundle.signed_prekey_private_key(), header.initiator_ephemeral_key());
    if (!dh3_res.is_ok()) {
        return application::ClientResult<X3dhResponderResult>::error(dh3_res.error());
    }

    std::optional<securecloud::common::configuration::SecretString> dh4_opt;
    if (otpk_priv_opt.has_value()) {
        auto dh4_res = crypto.diffie_hellman(*otpk_priv_opt, header.initiator_ephemeral_key());
        if (!dh4_res.is_ok()) {
            return application::ClientResult<X3dhResponderResult>::error(dh4_res.error());
        }
        dh4_opt = std::move(dh4_res).value();
    }

    // 3. Derive Master Shared Key
    auto sk_res = derive_x3dh_master_secret(crypto, dh1_res.value(), dh2_res.value(), dh3_res.value(), dh4_opt);
    if (!sk_res.is_ok()) {
        return application::ClientResult<X3dhResponderResult>::error(sk_res.error());
    }

    return application::ClientResult<X3dhResponderResult>::ok(X3dhResponderResult{
        .shared_secret = std::move(sk_res).value(), .claimed_one_time_prekey_id = std::move(claimed_otpk_id)});
}

} // namespace securecloud::client::domain::crypto
