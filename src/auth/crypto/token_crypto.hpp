#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::auth::crypto {

/**
 * @brief RFC 7515 URL-safe Base64 encoding and decoding utilities.
 */
class Base64Url {
  public:
    [[nodiscard]] static std::string encode(std::string_view input);
    [[nodiscard]] static std::string encode(const std::vector<uint8_t>& input);

    [[nodiscard]] static std::optional<std::string> decode(std::string_view input);
    [[nodiscard]] static std::optional<std::vector<uint8_t>> decode_bytes(std::string_view input);

    [[nodiscard]] static bool constant_time_equals(std::string_view a, std::string_view b) noexcept;
};

/**
 * @brief Abstract interface for asymmetric token signing.
 *
 * Implements the Auth Service boundary: Auth holds the private key and signs access tokens,
 * but never exposes its private key to external consumers or the Gateway.
 */
class ITokenSigner {
  public:
    virtual ~ITokenSigner() = default;

    /// Signs an arbitrary payload string and returns Base64URL encoded signature.
    [[nodiscard]] virtual std::string sign(std::string_view payload) const = 0;

    /// Exports public verification key in PEM format for downstream verification.
    [[nodiscard]] virtual std::string get_public_key_pem() const = 0;

    /// Exports public verification key as raw 32-byte Ed25519 representation.
    [[nodiscard]] virtual std::vector<uint8_t> get_public_key_raw() const = 0;

    /// Returns the unique key ID associated with this key pair.
    [[nodiscard]] virtual std::string get_key_id() const = 0;
};

/**
 * @brief Abstract interface for token signature verification.
 *
 * Can be instantiated anywhere (Auth Service, Gateway perimeter) using ONLY
 * the public verification key.
 */
class ITokenVerifier {
  public:
    virtual ~ITokenVerifier() = default;

    /// Verifies that the Base64URL encoded signature is valid for the payload.
    [[nodiscard]] virtual bool verify(std::string_view payload, std::string_view signature_base64url) const = 0;

    /// Verifies that the raw byte signature is valid for the payload.
    [[nodiscard]] virtual bool verify_raw(std::string_view payload,
                                          const std::vector<uint8_t>& signature_bytes) const = 0;

    /// Returns the key ID expected or associated with this verifier.
    [[nodiscard]] virtual std::string get_key_id() const = 0;
};

/**
 * @brief Native OpenSSL 3 implementation of Ed25519 asymmetric token signer.
 */
class Ed25519TokenSigner final : public ITokenSigner {
  public:
    /// Generates a new ephemeral Ed25519 keypair.
    explicit Ed25519TokenSigner(std::string key_id = "sc-auth-v1");

    /// Loads Ed25519 private key from PEM string.
    static std::unique_ptr<Ed25519TokenSigner> from_private_key_pem(std::string_view pem_content,
                                                                    std::string key_id = "sc-auth-v1");

    /// Exports private key in PEM format (Auth service internal persistence only).
    [[nodiscard]] std::string export_private_key_pem() const;

    ~Ed25519TokenSigner() override;

    // Non-copyable, movable
    Ed25519TokenSigner(const Ed25519TokenSigner&) = delete;
    Ed25519TokenSigner& operator=(const Ed25519TokenSigner&) = delete;
    Ed25519TokenSigner(Ed25519TokenSigner&& other) noexcept;
    Ed25519TokenSigner& operator=(Ed25519TokenSigner&& other) noexcept;

    [[nodiscard]] std::string sign(std::string_view payload) const override;
    [[nodiscard]] std::string get_public_key_pem() const override;
    [[nodiscard]] std::vector<uint8_t> get_public_key_raw() const override;
    [[nodiscard]] std::string get_key_id() const override;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::string key_id_;
};

/**
 * @brief Native OpenSSL 3 implementation of Ed25519 token verifier using public key only.
 */
class Ed25519TokenVerifier final : public ITokenVerifier {
  public:
    /// Constructs verifier from PEM formatted public key.
    static std::unique_ptr<Ed25519TokenVerifier> from_public_key_pem(std::string_view pem_content,
                                                                     std::string key_id = "sc-auth-v1");

    /// Constructs verifier from raw 32-byte Ed25519 public key.
    static std::unique_ptr<Ed25519TokenVerifier> from_public_key_raw(const std::vector<uint8_t>& raw_bytes,
                                                                     std::string key_id = "sc-auth-v1");

    /// Constructs verifier using public key extracted from an active signer.
    static std::unique_ptr<Ed25519TokenVerifier> from_signer(const ITokenSigner& signer);

    ~Ed25519TokenVerifier() override;

    // Non-copyable, movable
    Ed25519TokenVerifier(const Ed25519TokenVerifier&) = delete;
    Ed25519TokenVerifier& operator=(const Ed25519TokenVerifier&) = delete;
    Ed25519TokenVerifier(Ed25519TokenVerifier&& other) noexcept;
    Ed25519TokenVerifier& operator=(Ed25519TokenVerifier&& other) noexcept;

    [[nodiscard]] bool verify(std::string_view payload, std::string_view signature_base64url) const override;
    [[nodiscard]] bool verify_raw(std::string_view payload, const std::vector<uint8_t>& signature_bytes) const override;
    [[nodiscard]] std::string get_key_id() const override;

  private:
    Ed25519TokenVerifier();
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::string key_id_;
};

/**
 * @brief Cryptographically secure random token generator for single-use refresh tokens.
 */
class SecureRandomTokenGenerator {
  public:
    /// Generates 256-bit cryptographically secure random refresh token string formatted as "sc_rt_<base64url>".
    [[nodiscard]] static std::string generate_refresh_token(size_t entropy_bytes = 32);

    /// Generates raw cryptographically secure random bytes via OpenSSL RAND_bytes.
    [[nodiscard]] static std::vector<uint8_t> generate_secure_bytes(size_t byte_count);
};

/**
 * @brief Deterministic SHA-256 verifier computation for database storage.
 *
 * Refresh token secrets are NEVER persisted in plaintext. Only their SHA-256
 * verifier hashes are saved into the refresh_tokens table.
 */
class TokenHasher {
  public:
    /// Computes deterministic lowercase hex SHA-256 hash of token secret.
    [[nodiscard]] static std::string compute_sha256_hex(std::string_view secret);

    /// Constant-time verification helper to prevent timing attacks.
    [[nodiscard]] static bool verify_hash(std::string_view secret, std::string_view expected_hash_hex) noexcept;
};

} // namespace securecloud::auth::crypto
