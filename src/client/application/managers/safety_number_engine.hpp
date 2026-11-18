#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "domain/crypto_identity.hpp"
#include "domain/user_id.hpp"

#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace securecloud::client::application::managers {

class SafetyNumberEngine {
  public:
    static constexpr std::string_view kVerifiedKeyPrefix = "identity.verified.";

    SafetyNumberEngine(interfaces::ICryptoProvider& crypto_provider, interfaces::ISecureStorage& secure_storage);
    ~SafetyNumberEngine() = default;

    SafetyNumberEngine(const SafetyNumberEngine&) = delete;
    SafetyNumberEngine& operator=(const SafetyNumberEngine&) = delete;

    /// Derives the 60-digit safety number (12 blocks of 5 decimal digits)
    ClientResult<std::string> compute_safety_number(const domain::UserId& local_user_id,
                                                    std::span<const uint8_t> local_identity_key,
                                                    const domain::UserId& peer_user_id,
                                                    std::span<const uint8_t> peer_identity_key);

    /// Formats a raw 60-digit string into 12 blocks of 5 digits separated by spaces
    static std::string format_safety_number(std::string_view raw_digits);

    /// Validates and verifies an incoming peer identity key against locally stored verified state.
    /// Returns:
    /// - KeyVerificationStatus::Verified if fingerprint matches previously verified key
    /// - KeyVerificationStatus::KeyChanged if previous verified key exists and fingerprint differs
    /// - KeyVerificationStatus::Unverified if no previous verification record exists
    ClientResult<domain::KeyVerificationStatus>
    evaluate_key_verification_status(const domain::UserId& peer_user_id, std::span<const uint8_t> peer_identity_key);

    /// Stores or clears the peer's verified identity state in secure storage
    ClientResult<void> set_verification_state(const domain::UserId& peer_user_id,
                                              std::span<const uint8_t> peer_identity_key, bool verified);

    /// Retrieves the stored verified fingerprint for a peer (if any)
    ClientResult<std::optional<std::string>> get_verified_fingerprint(const domain::UserId& peer_user_id) const;

    /// Generates scannable verification URI: securecloud://verify?v=1&u1=...&u2=...&sn=...
    static std::string generate_verification_uri(const domain::UserId& local_user_id,
                                                 const domain::UserId& peer_user_id,
                                                 std::string_view formatted_safety_number);

    /// Structure holding parsed verification URI payload
    struct ParsedVerificationUri {
        domain::UserId user1;
        domain::UserId user2;
        std::string safety_number;
    };

    /// Parses verification URI and returns (user1, user2, formatted_safety_number)
    static ClientResult<ParsedVerificationUri> parse_verification_uri(std::string_view uri_str);

  private:
    interfaces::ICryptoProvider& crypto_provider_;
    interfaces::ISecureStorage& secure_storage_;
};

} // namespace securecloud::client::application::managers
