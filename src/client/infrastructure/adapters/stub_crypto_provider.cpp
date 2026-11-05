#include "infrastructure/adapters/stub_crypto_provider.hpp"

namespace securecloud::client::infrastructure::adapters {

application::ClientResult<domain::CryptoIdentity> StubCryptoProvider::generate_device_identity() {
    domain::CryptoIdentity identity("stub-public-identity-key-base64", "stub-fingerprint-hex-0001",
                                    domain::KeyVerificationStatus::Verified);
    return application::ClientResult<domain::CryptoIdentity>::ok(std::move(identity));
}

application::ClientResult<std::string> StubCryptoProvider::encrypt_message(const domain::DeviceId& recipient_device,
                                                                           std::string_view plaintext) {
    if (recipient_device.empty()) {
        return application::ClientResult<std::string>::error(
            application::ClientError::crypto("Recipient device cannot be empty"));
    }
    // Stub envelope creation for foundation architecture
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
