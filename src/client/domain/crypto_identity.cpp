#include "domain/crypto_identity.hpp"

#include <utility>

namespace securecloud::client::domain {

std::string_view to_string(KeyVerificationStatus status) noexcept {
    switch (status) {
    case KeyVerificationStatus::Unverified:
        return "Unverified";
    case KeyVerificationStatus::Verified:
        return "Verified";
    case KeyVerificationStatus::KeyChanged:
        return "KeyChanged";
    }
    return "Unknown";
}

CryptoIdentity::CryptoIdentity(std::string identity_key, std::string fingerprint,
                               KeyVerificationStatus verification_status, std::string signed_prekey,
                               std::string signature, std::chrono::system_clock::time_point created_at)
    : identity_key_(std::move(identity_key)), fingerprint_(std::move(fingerprint)),
      verification_status_(verification_status), signed_prekey_(std::move(signed_prekey)),
      signature_(std::move(signature)), created_at_(created_at) {}

bool CryptoIdentity::operator==(const CryptoIdentity& other) const noexcept {
    return identity_key_ == other.identity_key_ && fingerprint_ == other.fingerprint_ &&
           verification_status_ == other.verification_status_ && signed_prekey_ == other.signed_prekey_ &&
           signature_ == other.signature_;
}

} // namespace securecloud::client::domain
