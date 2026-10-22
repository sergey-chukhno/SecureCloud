#include "auth/service/mfa_authenticator_interface.hpp"

#include <openssl/crypto.h>
#include <stdexcept>

namespace securecloud::auth::service {

TotpAuthenticator::TotpAuthenticator(std::shared_ptr<crypto::TotpEngine> totp_engine,
                                     std::shared_ptr<crypto::MfaSecretProtector> secret_protector)
    : totp_engine_(std::move(totp_engine)), secret_protector_(std::move(secret_protector)) {
    if (!totp_engine_) {
        throw std::invalid_argument("TotpAuthenticator: totp_engine cannot be null");
    }
    if (!secret_protector_) {
        throw std::invalid_argument("TotpAuthenticator: secret_protector cannot be null");
    }
}

MfaFactorVerificationResult TotpAuthenticator::verify_factor(std::span<const uint8_t> encrypted_secret,
                                                             std::string_view credential, uint64_t timestamp_seconds,
                                                             std::string_view aad) const {
    if (encrypted_secret.empty()) {
        return MfaFactorVerificationResult::fail("Encrypted secret cannot be empty");
    }
    if (credential.empty()) {
        return MfaFactorVerificationResult::fail("Credential code cannot be empty");
    }

    std::vector<uint8_t> plaintext_secret;
    try {
        plaintext_secret = secret_protector_->decrypt(encrypted_secret, aad);
    } catch (const std::exception& ex) {
        return MfaFactorVerificationResult::fail(std::string("Secret decryption failed: ") + ex.what());
    }

    const auto res = totp_engine_->verify_code(plaintext_secret, credential, timestamp_seconds);

    // Securely scrub decrypted secret memory
    OPENSSL_cleanse(plaintext_secret.data(), plaintext_secret.size());

    if (!res.is_valid) {
        return MfaFactorVerificationResult::fail("Invalid TOTP verification code");
    }

    return MfaFactorVerificationResult::ok(res.matched_time_step);
}

} // namespace securecloud::auth::service
