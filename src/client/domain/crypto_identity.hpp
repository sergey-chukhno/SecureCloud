#pragma once

#include "domain/prekey_bundle.hpp"

#include <chrono>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::domain {

enum class KeyVerificationStatus { Unverified, Verified, KeyChanged };

[[nodiscard]] std::string_view to_string(KeyVerificationStatus status) noexcept;

class CryptoIdentity {
  public:
    CryptoIdentity() = default;

    CryptoIdentity(std::string identity_key, std::string fingerprint,
                   KeyVerificationStatus verification_status = KeyVerificationStatus::Unverified,
                   std::string signed_prekey = "", std::string signature = "",
                   std::chrono::system_clock::time_point created_at = std::chrono::system_clock::now());

    CryptoIdentity(std::span<const uint8_t> identity_key_bytes, std::string fingerprint,
                   KeyVerificationStatus verification_status = KeyVerificationStatus::Unverified,
                   std::span<const uint8_t> signed_prekey_bytes = {}, std::span<const uint8_t> signature_bytes = {},
                   std::chrono::system_clock::time_point created_at = std::chrono::system_clock::now());

    static CryptoIdentity
    from_prekey_bundle(const PrekeyBundle& bundle, std::string fingerprint,
                       KeyVerificationStatus verification_status = KeyVerificationStatus::Verified);

    [[nodiscard]] static bool is_valid_fingerprint(std::string_view fingerprint) noexcept;

    [[nodiscard]] const std::string& identity_key() const noexcept { return identity_key_; }
    [[nodiscard]] const std::string& fingerprint() const noexcept { return fingerprint_; }
    [[nodiscard]] KeyVerificationStatus verification_status() const noexcept { return verification_status_; }
    [[nodiscard]] const std::string& signed_prekey() const noexcept { return signed_prekey_; }
    [[nodiscard]] const std::string& signature() const noexcept { return signature_; }
    [[nodiscard]] std::chrono::system_clock::time_point created_at() const noexcept { return created_at_; }

    [[nodiscard]] std::vector<uint8_t> identity_key_bytes() const;
    [[nodiscard]] std::vector<uint8_t> signed_prekey_bytes() const;
    [[nodiscard]] std::vector<uint8_t> signature_bytes() const;

    void set_verification_status(KeyVerificationStatus status) noexcept { verification_status_ = status; }
    void set_fingerprint(std::string fingerprint) { fingerprint_ = std::move(fingerprint); }

    bool operator==(const CryptoIdentity& other) const noexcept;
    bool operator!=(const CryptoIdentity& other) const noexcept { return !(*this == other); }

  private:
    std::string identity_key_;
    std::string fingerprint_;
    KeyVerificationStatus verification_status_{KeyVerificationStatus::Unverified};
    std::string signed_prekey_;
    std::string signature_;
    std::chrono::system_clock::time_point created_at_{std::chrono::system_clock::now()};
};

} // namespace securecloud::client::domain
