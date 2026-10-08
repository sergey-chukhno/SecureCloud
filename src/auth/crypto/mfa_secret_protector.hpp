#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace securecloud::auth::crypto {

/**
 * @brief AES-256-GCM Authenticated Secret Protector for MFA credentials at rest.
 *
 * Implements authenticated encryption (AEAD) per NIST SP 800-38D using OpenSSL EVP.
 * Wire layout in PostgreSQL BYTEA:
 *   [ 12-byte random IV ] [ Ciphertext (N bytes) ] [ 16-byte GCM Authentication Tag ]
 *
 * Supports optional Additional Authenticated Data (AAD) to cryptographically bind
 * ciphertexts to their tenant/user context and prevent ciphertext transplantation.
 */
class MfaSecretProtector {
  public:
    static constexpr size_t kKeySize = 32;                       ///< 256-bit Key Encryption Key (KEK)
    static constexpr size_t kIvSize = 12;                        ///< 96-bit NIST standard GCM IV
    static constexpr size_t kTagSize = 16;                       ///< 128-bit GCM authentication tag
    static constexpr size_t kMinCipherSize = kIvSize + kTagSize; ///< 28 bytes minimum

    /**
     * @brief Constructs protector with a 32-byte binary key.
     */
    explicit MfaSecretProtector(std::span<const uint8_t, kKeySize> kek);

    /**
     * @brief Constructs protector from a raw 32-byte string or 64-character hexadecimal key.
     */
    explicit MfaSecretProtector(std::string_view hex_or_raw_key);

    ~MfaSecretProtector();

    MfaSecretProtector(const MfaSecretProtector&) = delete;
    MfaSecretProtector& operator=(const MfaSecretProtector&) = delete;
    MfaSecretProtector(MfaSecretProtector&&) noexcept;
    MfaSecretProtector& operator=(MfaSecretProtector&&) noexcept;

    /**
     * @brief Encrypts plaintext bytes using AES-256-GCM.
     * @param plaintext Sensitive secret bytes to protect.
     * @param aad Optional additional authenticated data (e.g., user_id).
     * @return Formatted vector containing [IV || Ciphertext || Tag].
     */
    [[nodiscard]] std::vector<uint8_t> encrypt(std::span<const uint8_t> plaintext, std::string_view aad = "") const;

    /**
     * @brief Decrypts and authenticates payload using AES-256-GCM.
     * @param encrypted_payload Payload containing [IV || Ciphertext || Tag].
     * @param aad Expected additional authenticated data.
     * @return Decrypted plaintext bytes.
     * @throws std::invalid_argument if payload is too short or malformed.
     * @throws std::runtime_error if authentication tag verification fails (tampering/wrong key).
     */
    [[nodiscard]] std::vector<uint8_t> decrypt(std::span<const uint8_t> encrypted_payload,
                                               std::string_view aad = "") const;

  private:
    std::array<uint8_t, kKeySize> kek_{};
};

} // namespace securecloud::auth::crypto
