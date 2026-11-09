#include "domain/crypto_identity.hpp"

#include <cctype>
#include <utility>

namespace securecloud::client::domain {

namespace {

std::string bytes_to_hex(std::span<const uint8_t> bytes) {
    constexpr char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const uint8_t b : bytes) {
        result.push_back(hex_chars[(b >> 4) & 0x0F]);
        result.push_back(hex_chars[b & 0x0F]);
    }
    return result;
}

int hex_char_to_val(char c) noexcept {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

std::vector<uint8_t> string_or_hex_to_bytes(std::string_view str) {
    if (str.empty()) {
        return {};
    }

    // Check if it's an even-length pure hex string
    if (str.size() % 2 == 0) {
        bool all_hex = true;
        for (const char c : str) {
            if (hex_char_to_val(c) < 0) {
                all_hex = false;
                break;
            }
        }
        if (all_hex) {
            std::vector<uint8_t> bytes;
            bytes.reserve(str.size() / 2);
            for (std::size_t i = 0; i < str.size(); i += 2) {
                const int high = hex_char_to_val(str[i]);
                const int low = hex_char_to_val(str[i + 1]);
                bytes.push_back(static_cast<uint8_t>((high << 4) | low));
            }
            return bytes;
        }
    }

    // Otherwise treat as raw byte sequence
    return std::vector<uint8_t>(str.begin(), str.end());
}

} // namespace

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

CryptoIdentity::CryptoIdentity(std::span<const uint8_t> identity_key_bytes, std::string fingerprint,
                               KeyVerificationStatus verification_status, std::span<const uint8_t> signed_prekey_bytes,
                               std::span<const uint8_t> signature_bytes,
                               std::chrono::system_clock::time_point created_at)
    : identity_key_(bytes_to_hex(identity_key_bytes)), fingerprint_(std::move(fingerprint)),
      verification_status_(verification_status), signed_prekey_(bytes_to_hex(signed_prekey_bytes)),
      signature_(bytes_to_hex(signature_bytes)), created_at_(created_at) {}

CryptoIdentity CryptoIdentity::from_prekey_bundle(const PrekeyBundle& bundle, std::string fingerprint,
                                                  KeyVerificationStatus verification_status) {
    return CryptoIdentity(bundle.identity_key_hex(), std::move(fingerprint), verification_status,
                          bundle.signed_prekey_hex(), bundle.signed_prekey_signature_hex(), bundle.created_at());
}

bool CryptoIdentity::is_valid_fingerprint(std::string_view fingerprint) noexcept {
    // Expected format: "SHA256:XX:XX:..." (32 hex bytes in uppercase, separated by colons)
    // Total size: 7 ("SHA256:") + (32 * 2) + 31 = 102 chars
    if (fingerprint.size() != 102) {
        return false;
    }
    if (!fingerprint.starts_with("SHA256:")) {
        return false;
    }
    for (std::size_t i = 7; i < 102; ++i) {
        if ((i - 7) % 3 == 2) {
            if (fingerprint[i] != ':') {
                return false;
            }
        } else {
            const char c = fingerprint[i];
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) {
                return false;
            }
        }
    }
    return true;
}

std::vector<uint8_t> CryptoIdentity::identity_key_bytes() const {
    return string_or_hex_to_bytes(identity_key_);
}

std::vector<uint8_t> CryptoIdentity::signed_prekey_bytes() const {
    return string_or_hex_to_bytes(signed_prekey_);
}

std::vector<uint8_t> CryptoIdentity::signature_bytes() const {
    return string_or_hex_to_bytes(signature_);
}

bool CryptoIdentity::operator==(const CryptoIdentity& other) const noexcept {
    return identity_key_ == other.identity_key_ && fingerprint_ == other.fingerprint_ &&
           verification_status_ == other.verification_status_ && signed_prekey_ == other.signed_prekey_ &&
           signature_ == other.signature_;
}

} // namespace securecloud::client::domain
