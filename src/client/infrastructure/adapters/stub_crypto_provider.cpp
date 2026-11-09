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

} // namespace securecloud::client::infrastructure::adapters
