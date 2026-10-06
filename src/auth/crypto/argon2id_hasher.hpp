#pragma once

#include "crypto/password_hasher.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace securecloud::auth::crypto {

/// Configuration parameters for Argon2id key derivation (RFC 9106).
struct Argon2idConfig {
    /// Memory hardness cost in KiB (e.g. 65536 = 64 MiB).
    std::uint32_t memory_cost_kib{65536};

    /// Number of time iterations (passes over memory).
    std::uint32_t iterations{3};

    /// Number of parallel threads/lanes.
    std::uint32_t parallelism{1};

    /// Cryptographically secure random salt size in bytes.
    std::size_t salt_length{16};

    /// Output derived key length in bytes.
    std::size_t hash_length{32};
};

/// Production implementation of IPasswordHasher utilizing OpenSSL 3 native EVP_KDF
/// for Argon2id derivation with standard RFC 9106 PHC string formatting.
class OpenSslArgon2idHasher final : public IPasswordHasher {
  public:
    explicit OpenSslArgon2idHasher(Argon2idConfig config = Argon2idConfig{});
    ~OpenSslArgon2idHasher() override = default;

    OpenSslArgon2idHasher(const OpenSslArgon2idHasher&) = delete;
    OpenSslArgon2idHasher& operator=(const OpenSslArgon2idHasher&) = delete;
    OpenSslArgon2idHasher(OpenSslArgon2idHasher&&) noexcept = default;
    OpenSslArgon2idHasher& operator=(OpenSslArgon2idHasher&&) noexcept = default;

    /// Hashes the given secret password with Argon2id and generates a standard PHC string:
    /// $argon2id$v=19$m=<m>,t=<t>,p=<p>$<salt_b64>$<hash_b64>
    std::string hash_password(const common::configuration::SecretString& password) override;

    /// Verifies the secret password against a PHC verifier string in constant time.
    /// Returns false if verifier is malformed or password does not match.
    bool verify_password(const common::configuration::SecretString& password,
                         std::string_view stored_verifier) override;

    /// Runs Argon2id verification against a pre-generated internal dummy verifier to ensure
    /// identical computational latency for non-existent accounts.
    void execute_dummy_verification(const common::configuration::SecretString& password) override;

    /// Returns the active configuration parameters.
    [[nodiscard]] const Argon2idConfig& config() const noexcept { return config_; }

  private:
    Argon2idConfig config_;
    std::string dummy_verifier_;
};

} // namespace securecloud::auth::crypto
