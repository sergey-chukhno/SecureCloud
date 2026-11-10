#include "domain/crypto/double_ratchet_engine.hpp"

#include <openssl/crypto.h>

namespace securecloud::client::domain::crypto {

namespace {

application::ClientResult<
    std::pair<securecloud::common::configuration::SecretString, securecloud::common::configuration::SecretString>>
kdf_rk(application::interfaces::ICryptoProvider& crypto,
       const securecloud::common::configuration::SecretString& root_key,
       const securecloud::common::configuration::SecretString& dh_out) {
    const auto& rk_bytes = root_key.expose_unredacted_secret();
    std::span<const uint8_t> rk_span(reinterpret_cast<const uint8_t*>(rk_bytes.data()), rk_bytes.size());

    const std::string_view info = DoubleRatchetEngine::kRootRatchetInfo;
    std::span<const uint8_t> info_span(reinterpret_cast<const uint8_t*>(info.data()), info.size());

    auto derive_res = crypto.hkdf_extract_and_expand(rk_span, dh_out, info_span, 64);
    if (!derive_res.is_ok()) {
        return application::ClientResult<
            std::pair<securecloud::common::configuration::SecretString,
                      securecloud::common::configuration::SecretString>>::error(derive_res.error());
    }

    const auto& out_bytes = derive_res.value().expose_unredacted_secret();
    if (out_bytes.size() != 64) {
        return application::ClientResult<std::pair<securecloud::common::configuration::SecretString,
                                                   securecloud::common::configuration::SecretString>>::
            error(application::ClientError::crypto("KDF_RK expected 64-byte output"));
    }

    std::string new_rk = out_bytes.substr(0, 32);
    std::string new_ck = out_bytes.substr(32, 32);

    return application::ClientResult<
        std::pair<securecloud::common::configuration::SecretString, securecloud::common::configuration::SecretString>>::
        ok(std::make_pair(securecloud::common::configuration::SecretString(std::move(new_rk)),
                          securecloud::common::configuration::SecretString(std::move(new_ck))));
}

application::ClientResult<
    std::pair<securecloud::common::configuration::SecretString, securecloud::common::configuration::SecretString>>
kdf_ck(application::interfaces::ICryptoProvider& crypto,
       const securecloud::common::configuration::SecretString& chain_key) {
    const std::string_view info = DoubleRatchetEngine::kChainRatchetInfo;
    std::span<const uint8_t> info_span(reinterpret_cast<const uint8_t*>(info.data()), info.size());

    auto expand_res = crypto.hkdf_expand(chain_key, info_span, 64);
    if (!expand_res.is_ok()) {
        return application::ClientResult<
            std::pair<securecloud::common::configuration::SecretString,
                      securecloud::common::configuration::SecretString>>::error(expand_res.error());
    }

    const auto& out_bytes = expand_res.value().expose_unredacted_secret();
    if (out_bytes.size() != 64) {
        return application::ClientResult<std::pair<securecloud::common::configuration::SecretString,
                                                   securecloud::common::configuration::SecretString>>::
            error(application::ClientError::crypto("KDF_CK expected 64-byte output"));
    }

    std::string message_key = out_bytes.substr(0, 32);
    std::string next_chain_key = out_bytes.substr(32, 32);

    return application::ClientResult<
        std::pair<securecloud::common::configuration::SecretString, securecloud::common::configuration::SecretString>>::
        ok(std::make_pair(securecloud::common::configuration::SecretString(std::move(message_key)),
                          securecloud::common::configuration::SecretString(std::move(next_chain_key))));
}

application::ClientResult<std::vector<uint8_t>>
derive_iv(application::interfaces::ICryptoProvider& crypto,
          const securecloud::common::configuration::SecretString& message_key) {
    constexpr std::string_view kIvInfo = "SecureCloud-MessageIV-v1";
    std::span<const uint8_t> info_span(reinterpret_cast<const uint8_t*>(kIvInfo.data()), kIvInfo.size());

    auto res = crypto.hkdf_expand(message_key, info_span, PrekeyPolicy::kAeadGcmIvSize);
    if (!res.is_ok()) {
        return application::ClientResult<std::vector<uint8_t>>::error(res.error());
    }

    const auto& iv_bytes = res.value().expose_unredacted_secret();
    return application::ClientResult<std::vector<uint8_t>>::ok(std::vector<uint8_t>(iv_bytes.begin(), iv_bytes.end()));
}

} // namespace

application::ClientResult<RatchetState>
DoubleRatchetEngine::initialize_alice(application::interfaces::ICryptoProvider& crypto,
                                      const securecloud::common::configuration::SecretString& shared_secret,
                                      std::span<const uint8_t> bob_dh_pub) {
    if (shared_secret.size() != PrekeyPolicy::kSharedSecretSize) {
        return application::ClientResult<RatchetState>::error(
            application::ClientError::crypto("DoubleRatchet shared secret must be 32 bytes"));
    }
    if (bob_dh_pub.size() != PrekeyPolicy::kX25519PublicKeySize) {
        return application::ClientResult<RatchetState>::error(
            application::ClientError::crypto("Bob's DH public key must be 32 bytes"));
    }

    // 1. Alice generates initial sending DH keypair
    auto dh_res = crypto.generate_dh_keypair();
    if (!dh_res.is_ok()) {
        return application::ClientResult<RatchetState>::error(dh_res.error());
    }
    auto dh_pair = std::move(dh_res).value();

    // 2. Perform initial DH derivation with Bob's public prekey
    auto dh_out_res = crypto.diffie_hellman(dh_pair.private_key, bob_dh_pub);
    if (!dh_out_res.is_ok()) {
        return application::ClientResult<RatchetState>::error(dh_out_res.error());
    }

    // 3. Step root KDF to initialize root key and Alice's sending chain
    auto rk_res = kdf_rk(crypto, shared_secret, dh_out_res.value());
    if (!rk_res.is_ok()) {
        return application::ClientResult<RatchetState>::error(rk_res.error());
    }
    auto [root_key, sending_ck] = std::move(rk_res).value();

    RatchetState state{
        .root_key = std::move(root_key),
        .sending_dh_pair = std::move(dh_pair),
        .peer_dh_pub = std::vector<uint8_t>(bob_dh_pub.begin(), bob_dh_pub.end()),
        .sending_chain_key = std::move(sending_ck),
        .receiving_chain_key = securecloud::common::configuration::SecretString(""),
        .ns = 0,
        .nr = 0,
        .pn = 0,
    };

    return application::ClientResult<RatchetState>::ok(std::move(state));
}

application::ClientResult<RatchetState>
DoubleRatchetEngine::initialize_bob(application::interfaces::ICryptoProvider& /*crypto*/,
                                    const securecloud::common::configuration::SecretString& shared_secret,
                                    application::interfaces::DhKeyPair bob_dh_keypair) {
    if (shared_secret.size() != PrekeyPolicy::kSharedSecretSize) {
        return application::ClientResult<RatchetState>::error(
            application::ClientError::crypto("DoubleRatchet shared secret must be 32 bytes"));
    }
    if (bob_dh_keypair.public_key.size() != PrekeyPolicy::kX25519PublicKeySize ||
        bob_dh_keypair.private_key.size() != PrekeyPolicy::kX25519PrivateKeySize) {
        return application::ClientResult<RatchetState>::error(
            application::ClientError::crypto("Bob's DH keypair must be 32 bytes"));
    }

    RatchetState state{
        .root_key = shared_secret,
        .sending_dh_pair = std::move(bob_dh_keypair),
        .peer_dh_pub = {},
        .sending_chain_key = securecloud::common::configuration::SecretString(""),
        .receiving_chain_key = securecloud::common::configuration::SecretString(""),
        .ns = 0,
        .nr = 0,
        .pn = 0,
    };

    return application::ClientResult<RatchetState>::ok(std::move(state));
}

application::ClientResult<DoubleRatchetMessage>
DoubleRatchetEngine::ratchet_encrypt(application::interfaces::ICryptoProvider& crypto, RatchetState& state,
                                     std::span<const uint8_t> plaintext) {
    // If sending chain is not yet initialized (e.g. Bob sending before reply or after a turn)
    if (state.sending_chain_key.empty()) {
        if (state.peer_dh_pub.empty()) {
            return application::ClientResult<DoubleRatchetMessage>::error(
                application::ClientError::crypto("Cannot encrypt: missing peer DH public key"));
        }

        auto new_dh_res = crypto.generate_dh_keypair();
        if (!new_dh_res.is_ok()) {
            return application::ClientResult<DoubleRatchetMessage>::error(new_dh_res.error());
        }
        state.sending_dh_pair = std::move(new_dh_res).value();

        auto dh_out_res = crypto.diffie_hellman(state.sending_dh_pair.private_key, state.peer_dh_pub);
        if (!dh_out_res.is_ok()) {
            return application::ClientResult<DoubleRatchetMessage>::error(dh_out_res.error());
        }

        auto rk_res = kdf_rk(crypto, state.root_key, dh_out_res.value());
        if (!rk_res.is_ok()) {
            return application::ClientResult<DoubleRatchetMessage>::error(rk_res.error());
        }
        state.root_key = std::move(rk_res.value().first);
        state.sending_chain_key = std::move(rk_res.value().second);
        state.pn = state.ns;
        state.ns = 0;
    }

    // Advance symmetric chain: (MK, CK_next) = KDF_CK(CK)
    auto ck_res = kdf_ck(crypto, state.sending_chain_key);
    if (!ck_res.is_ok()) {
        return application::ClientResult<DoubleRatchetMessage>::error(ck_res.error());
    }
    auto [message_key, next_ck] = std::move(ck_res).value();
    state.sending_chain_key = std::move(next_ck);

    // Construct header
    RatchetHeader header(state.sending_dh_pair.public_key, state.pn, state.ns);
    state.ns++;

    // Derive deterministic IV from MK and serialize header as AAD
    auto iv_res = derive_iv(crypto, message_key);
    if (!iv_res.is_ok()) {
        return application::ClientResult<DoubleRatchetMessage>::error(iv_res.error());
    }
    const auto iv = std::move(iv_res).value();
    const auto aad = header.serialize();

    // Encrypt payload with AES-256-GCM
    auto enc_res = crypto.encrypt_aes_gcm(message_key, iv, plaintext, aad);
    if (!enc_res.is_ok()) {
        return application::ClientResult<DoubleRatchetMessage>::error(enc_res.error());
    }

    return application::ClientResult<DoubleRatchetMessage>::ok(
        DoubleRatchetMessage{.header = std::move(header),
                             .ciphertext = std::move(enc_res.value().ciphertext),
                             .iv = std::move(enc_res.value().iv),
                             .auth_tag = std::move(enc_res.value().auth_tag)});
}

application::ClientResult<securecloud::common::configuration::SecretString>
DoubleRatchetEngine::ratchet_decrypt(application::interfaces::ICryptoProvider& crypto, RatchetState& state,
                                     const DoubleRatchetMessage& message) {
    const auto& header = message.header;
    const bool is_dh_turn = state.peer_dh_pub.empty() || header.dh_pub() != state.peer_dh_pub;

    if (is_dh_turn) {
        // Step 1: Receiving Turn — fold peer's new DH key into root key
        auto dh_recv_res = crypto.diffie_hellman(state.sending_dh_pair.private_key, header.dh_pub());
        if (!dh_recv_res.is_ok()) {
            return application::ClientResult<securecloud::common::configuration::SecretString>::error(
                dh_recv_res.error());
        }

        auto rk_recv_res = kdf_rk(crypto, state.root_key, dh_recv_res.value());
        if (!rk_recv_res.is_ok()) {
            return application::ClientResult<securecloud::common::configuration::SecretString>::error(
                rk_recv_res.error());
        }
        state.root_key = std::move(rk_recv_res.value().first);
        state.receiving_chain_key = std::move(rk_recv_res.value().second);
        state.peer_dh_pub = header.dh_pub();
        state.pn = state.ns;
        state.ns = 0;
        state.nr = 0;

        // Step 2: Sending Turn — generate fresh DH keypair and fold into root key for our next sends
        auto new_dh_res = crypto.generate_dh_keypair();
        if (!new_dh_res.is_ok()) {
            return application::ClientResult<securecloud::common::configuration::SecretString>::error(
                new_dh_res.error());
        }
        state.sending_dh_pair = std::move(new_dh_res).value();

        auto dh_send_res = crypto.diffie_hellman(state.sending_dh_pair.private_key, state.peer_dh_pub);
        if (!dh_send_res.is_ok()) {
            return application::ClientResult<securecloud::common::configuration::SecretString>::error(
                dh_send_res.error());
        }

        auto rk_send_res = kdf_rk(crypto, state.root_key, dh_send_res.value());
        if (!rk_send_res.is_ok()) {
            return application::ClientResult<securecloud::common::configuration::SecretString>::error(
                rk_send_res.error());
        }
        state.root_key = std::move(rk_send_res.value().first);
        state.sending_chain_key = std::move(rk_send_res.value().second);
    }

    if (state.receiving_chain_key.empty()) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Cannot decrypt: receiving chain key is uninitialized"));
    }

    // Advance symmetric receiving chain: (MK, CK_next) = KDF_CK(CK_r)
    auto ck_res = kdf_ck(crypto, state.receiving_chain_key);
    if (!ck_res.is_ok()) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(ck_res.error());
    }
    auto [message_key, next_ck] = std::move(ck_res).value();
    state.receiving_chain_key = std::move(next_ck);
    state.nr++;

    // Validate and decrypt with AES-256-GCM using serialized header as AAD
    const auto aad = header.serialize();
    return crypto.decrypt_aes_gcm(message_key, message.iv, message.ciphertext, message.auth_tag, aad);
}

} // namespace securecloud::client::domain::crypto
