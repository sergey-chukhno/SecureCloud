#include "auth/crypto/prekey_signature_verifier.hpp"

#include "auth/crypto/device_key_validator.hpp"

namespace securecloud::auth::crypto {

bool PrekeySignatureVerifier::verify(std::span<const uint8_t> identity_key, std::span<const uint8_t> signed_prekey,
                                     std::span<const uint8_t> signature, std::string* error_out) {
    return DeviceKeyValidator::validate_signed_prekey_signature(identity_key, signed_prekey, signature, error_out);
}

} // namespace securecloud::auth::crypto
