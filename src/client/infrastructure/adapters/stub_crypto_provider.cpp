#include "infrastructure/adapters/stub_crypto_provider.hpp"

#include "domain/prekey_policy.hpp"

namespace securecloud::client::infrastructure::adapters {

application::ClientResult<application::interfaces::IdentityKeyPair> StubCryptoProvider::generate_identity_keypair() {
    std::vector<uint8_t> pub(domain::PrekeyPolicy::kEd25519PublicKeySize, 0x11);
    std::string priv_str(domain::PrekeyPolicy::kEd25519PrivateKeySize, '\x12');
    return application::ClientResult<application::interfaces::IdentityKeyPair>::ok(
        application::interfaces::IdentityKeyPair{
            .public_key = std::move(pub),
            .private_key = securecloud::common::configuration::SecretString(std::move(priv_str)),
        });
}

application::ClientResult<application::interfaces::SignedPrekeyResult> StubCryptoProvider::generate_signed_prekey(
    const securecloud::common::configuration::SecretString& identity_private_key) {
    if (identity_private_key.empty()) {
        return application::ClientResult<application::interfaces::SignedPrekeyResult>::error(
            application::ClientError::crypto("Identity private key cannot be empty"));
    }
    std::vector<uint8_t> pub(domain::PrekeyPolicy::kX25519PublicKeySize, 0x21);
    std::string priv_str(domain::PrekeyPolicy::kX25519PrivateKeySize, '\x22');
    std::vector<uint8_t> sig(domain::PrekeyPolicy::kEd25519SignatureSize, 0x23);

    return application::ClientResult<application::interfaces::SignedPrekeyResult>::ok(
        application::interfaces::SignedPrekeyResult{
            .public_key = std::move(pub),
            .private_key = securecloud::common::configuration::SecretString(std::move(priv_str)),
            .signature = std::move(sig),
        });
}

application::ClientResult<bool>
StubCryptoProvider::verify_signed_prekey(std::span<const uint8_t> identity_public_key,
                                         std::span<const uint8_t> signed_prekey_public_key,
                                         std::span<const uint8_t> signature) {
    if (identity_public_key.size() != domain::PrekeyPolicy::kEd25519PublicKeySize ||
        signed_prekey_public_key.size() != domain::PrekeyPolicy::kX25519PublicKeySize ||
        signature.size() != domain::PrekeyPolicy::kEd25519SignatureSize) {
        return application::ClientResult<bool>::ok(false);
    }
    return application::ClientResult<bool>::ok(true);
}

application::ClientResult<std::vector<application::interfaces::OneTimePrekeyPair>>
StubCryptoProvider::generate_one_time_prekeys(std::size_t count, std::size_t start_index) {
    std::vector<application::interfaces::OneTimePrekeyPair> result;
    result.reserve(count);

    for (std::size_t i = 0; i < count; ++i) {
        std::vector<uint8_t> pub(domain::PrekeyPolicy::kX25519PublicKeySize, static_cast<uint8_t>(0x30 + (i % 10)));
        std::string priv_str(domain::PrekeyPolicy::kX25519PrivateKeySize, static_cast<char>(0x40 + (i % 10)));
        result.push_back(application::interfaces::OneTimePrekeyPair{
            .record = domain::OneTimePrekeyRecord(std::to_string(start_index + i), std::move(pub)),
            .private_key = securecloud::common::configuration::SecretString(std::move(priv_str)),
        });
    }

    return application::ClientResult<std::vector<application::interfaces::OneTimePrekeyPair>>::ok(std::move(result));
}

application::ClientResult<std::string>
StubCryptoProvider::compute_identity_fingerprint(std::span<const uint8_t> identity_public_key) {
    if (identity_public_key.empty()) {
        return application::ClientResult<std::string>::error(
            application::ClientError::crypto("Identity public key cannot be empty"));
    }
    // Stub valid fingerprint format
    return application::ClientResult<std::string>::ok(
        "SHA256:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF");
}

application::ClientResult<domain::CryptoIdentity> StubCryptoProvider::generate_device_identity() {
    domain::CryptoIdentity identity(
        "stub-public-identity-key-base64",
        "SHA256:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF",
        domain::KeyVerificationStatus::Verified);
    return application::ClientResult<domain::CryptoIdentity>::ok(std::move(identity));
}

application::ClientResult<std::string> StubCryptoProvider::encrypt_message(const domain::DeviceId& recipient_device,
                                                                           std::string_view plaintext) {
    if (recipient_device.empty()) {
        return application::ClientResult<std::string>::error(
            application::ClientError::crypto("Recipient device cannot be empty"));
    }
    return application::ClientResult<std::string>::ok("encrypted:" + std::string(plaintext));
}

application::ClientResult<std::string> StubCryptoProvider::decrypt_message(const domain::DeviceId& sender_device,
                                                                           std::string_view ciphertext) {
    if (sender_device.empty()) {
        return application::ClientResult<std::string>::error(
            application::ClientError::crypto("Sender device cannot be empty"));
    }
    const std::string prefix = "encrypted:";
    if (ciphertext.rfind(prefix, 0) == 0) {
        return application::ClientResult<std::string>::ok(std::string(ciphertext.substr(prefix.size())));
    }
    return application::ClientResult<std::string>::ok(std::string(ciphertext));
}

application::ClientResult<bool> StubCryptoProvider::verify_identity_fingerprint(const domain::DeviceId& device,
                                                                                std::string_view fingerprint) {
    if (device.empty() || fingerprint.empty()) {
        return application::ClientResult<bool>::ok(false);
    }
    return application::ClientResult<bool>::ok(true);
}

application::ClientResult<application::interfaces::DhKeyPair> StubCryptoProvider::generate_dh_keypair() {
    std::vector<uint8_t> pub(domain::PrekeyPolicy::kX25519PublicKeySize, 0x51);
    std::string priv(domain::PrekeyPolicy::kX25519PrivateKeySize, '\x52');
    return application::ClientResult<application::interfaces::DhKeyPair>::ok(application::interfaces::DhKeyPair{
        .public_key = std::move(pub),
        .private_key = securecloud::common::configuration::SecretString(std::move(priv)),
    });
}

application::ClientResult<securecloud::common::configuration::SecretString>
StubCryptoProvider::diffie_hellman(const securecloud::common::configuration::SecretString& our_private_key,
                                   std::span<const uint8_t> peer_public_key) {
    if (our_private_key.size() != domain::PrekeyPolicy::kX25519PrivateKeySize ||
        peer_public_key.size() != domain::PrekeyPolicy::kX25519PublicKeySize) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Diffie-Hellman keys must be exactly 32 bytes"));
    }
    std::string secret(domain::PrekeyPolicy::kSharedSecretSize, '\0');
    const auto& priv_bytes = our_private_key.expose_unredacted_secret();
    for (std::size_t i = 0; i < domain::PrekeyPolicy::kSharedSecretSize; ++i) {
        secret[i] = static_cast<char>(static_cast<uint8_t>(priv_bytes[i]) ^ peer_public_key[i]);
    }
    return application::ClientResult<securecloud::common::configuration::SecretString>::ok(
        securecloud::common::configuration::SecretString(std::move(secret)));
}

application::ClientResult<securecloud::common::configuration::SecretString>
StubCryptoProvider::hkdf_extract(std::span<const uint8_t> salt,
                                 const securecloud::common::configuration::SecretString& ikm) {
    if (ikm.empty()) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("HKDF IKM cannot be empty"));
    }
    std::string prk(32, '\0');
    const auto& ikm_bytes = ikm.expose_unredacted_secret();
    for (std::size_t i = 0; i < 32; ++i) {
        uint8_t s = salt.empty() ? 0 : salt[i % salt.size()];
        uint8_t k = static_cast<uint8_t>(ikm_bytes[i % ikm_bytes.size()]);
        prk[i] = static_cast<char>(s ^ k);
    }
    return application::ClientResult<securecloud::common::configuration::SecretString>::ok(
        securecloud::common::configuration::SecretString(std::move(prk)));
}

application::ClientResult<securecloud::common::configuration::SecretString>
StubCryptoProvider::hkdf_expand(const securecloud::common::configuration::SecretString& prk,
                                std::span<const uint8_t> info, std::size_t length) {
    if (prk.empty() || length == 0) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("HKDF Expand invalid parameters"));
    }
    std::string okm(length, '\0');
    const auto& prk_bytes = prk.expose_unredacted_secret();
    for (std::size_t i = 0; i < length; ++i) {
        uint8_t p = static_cast<uint8_t>(prk_bytes[i % prk_bytes.size()]);
        uint8_t inf = info.empty() ? 0 : info[i % info.size()];
        okm[i] = static_cast<char>(p ^ inf ^ static_cast<uint8_t>(i));
    }
    return application::ClientResult<securecloud::common::configuration::SecretString>::ok(
        securecloud::common::configuration::SecretString(std::move(okm)));
}

application::ClientResult<securecloud::common::configuration::SecretString>
StubCryptoProvider::hkdf_extract_and_expand(std::span<const uint8_t> salt,
                                            const securecloud::common::configuration::SecretString& ikm,
                                            std::span<const uint8_t> info, std::size_t length) {
    auto prk_res = hkdf_extract(salt, ikm);
    if (!prk_res.is_ok()) {
        return prk_res;
    }
    return hkdf_expand(prk_res.value(), info, length);
}

application::ClientResult<application::interfaces::AeadCiphertext>
StubCryptoProvider::encrypt_aes_gcm(const securecloud::common::configuration::SecretString& key,
                                    std::span<const uint8_t> iv, std::span<const uint8_t> plaintext,
                                    std::span<const uint8_t> /*associated_data*/) {
    if (key.size() != domain::PrekeyPolicy::kAes256KeySize) {
        return application::ClientResult<application::interfaces::AeadCiphertext>::error(
            application::ClientError::crypto("AES key must be 32 bytes"));
    }
    if (iv.size() != domain::PrekeyPolicy::kAeadGcmIvSize) {
        return application::ClientResult<application::interfaces::AeadCiphertext>::error(
            application::ClientError::crypto("AES GCM IV must be 12 bytes"));
    }

    std::vector<uint8_t> ct(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> iv_copy(iv.begin(), iv.end());
    std::vector<uint8_t> tag(domain::PrekeyPolicy::kAeadGcmTagSize, 0xAA);

    return application::ClientResult<application::interfaces::AeadCiphertext>::ok(
        application::interfaces::AeadCiphertext{
            .ciphertext = std::move(ct),
            .iv = std::move(iv_copy),
            .auth_tag = std::move(tag),
        });
}

application::ClientResult<securecloud::common::configuration::SecretString>
StubCryptoProvider::decrypt_aes_gcm(const securecloud::common::configuration::SecretString& key,
                                    std::span<const uint8_t> iv, std::span<const uint8_t> ciphertext,
                                    std::span<const uint8_t> auth_tag, std::span<const uint8_t> /*associated_data*/) {
    if (key.size() != domain::PrekeyPolicy::kAes256KeySize) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("AES key must be 32 bytes"));
    }
    if (iv.size() != domain::PrekeyPolicy::kAeadGcmIvSize) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("AES GCM IV must be 12 bytes"));
    }
    if (auth_tag.size() != domain::PrekeyPolicy::kAeadGcmTagSize) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("AES GCM tag must be 16 bytes"));
    }

    std::string pt(ciphertext.begin(), ciphertext.end());
    return application::ClientResult<securecloud::common::configuration::SecretString>::ok(
        securecloud::common::configuration::SecretString(std::move(pt)));
}

application::ClientResult<std::string> StubCryptoProvider::compute_safety_number(
    const domain::UserId& local_user_id, std::span<const uint8_t> local_identity_key,
    const domain::UserId& peer_user_id, std::span<const uint8_t> peer_identity_key) {
    if (local_user_id.empty() || peer_user_id.empty() ||
        local_identity_key.size() != domain::PrekeyPolicy::kEd25519PublicKeySize ||
        peer_identity_key.size() != domain::PrekeyPolicy::kEd25519PublicKeySize) {
        return application::ClientResult<std::string>::error(
            application::ClientError::crypto("Invalid parameters for safety number computation"));
    }
    return application::ClientResult<std::string>::ok(
        "10928 38471 66251 89201 44712 09182 55910 28471 90284 71209 38471 09284");
}

} // namespace securecloud::client::infrastructure::adapters
