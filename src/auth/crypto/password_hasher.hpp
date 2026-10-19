#pragma once

#include <securecloud/configuration/secret_string.hpp>
#include <string>
#include <string_view>

namespace securecloud::auth::crypto {

/// Abstract interface for cryptographic password hashing and verification.
/// Implementations must guarantee constant-time verification comparisons,
/// zero plaintext password retention, and resistance to user enumeration.
class IPasswordHasher {
  public:
    virtual ~IPasswordHasher() = default;

    /// Hashes the given secret password and produces a standard PHC-formatted verifier string.
    ///
    /// @param password Secret container wrapping the plaintext password.
    /// @return Standard PHC string (e.g. $argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>).
    virtual std::string hash_password(const common::configuration::SecretString& password) = 0;

    /// Verifies the given secret password against a stored PHC-formatted verifier string
    /// in constant time to prevent side-channel timing attacks.
    ///
    /// @param password Plaintext candidate password wrapped in SecretString.
    /// @param stored_verifier PHC-formatted Argon2id verifier string.
    /// @return true if password matches verifier, false otherwise (fails closed on malformed input).
    virtual bool verify_password(const common::configuration::SecretString& password,
                                 std::string_view stored_verifier) = 0;

    /// Executes a dummy verification operation with computationally equivalent work
    /// (same memory cost and iterations) to defend against timing-based user enumeration
    /// when an authentication request specifies a non-existent account.
    ///
    /// @param password Plaintext candidate password wrapped in SecretString.
    virtual void execute_dummy_verification(const common::configuration::SecretString& password) = 0;
};

} // namespace securecloud::auth::crypto
