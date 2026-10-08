#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::auth::crypto {

/**
 * @brief Batch of generated emergency disaster recovery codes.
 */
struct RecoveryCodeBatch {
    std::vector<std::string> plaintext_codes; ///< Human-readable codes returned ONCE to the user
    std::vector<std::string> hashed_codes;    ///< Hex-encoded SHA-256 hashes stored in PostgreSQL
};

/**
 * @brief Generator, hasher, and validator for single-use disaster recovery backup codes.
 *
 * Generates cryptographically secure, high-entropy alphanumeric codes formatted for
 * human readability (e.g., "7K9A-4B2C"). Codes are hashed with SHA-256 before storage
 * to guarantee that database compromises do not expose valid emergency credentials.
 */
class RecoveryCodeGenerator {
  public:
    static constexpr size_t kDefaultCodeCount = 8;

    /**
     * @brief Generates a new batch of random recovery codes and their SHA-256 hashes.
     * @param count Number of codes to generate (default 8).
     * @return Batch containing plaintext codes and matching hashed values.
     */
    [[nodiscard]] static RecoveryCodeBatch generate_batch(size_t count = kDefaultCodeCount);

    /**
     * @brief Normalizes a recovery code (stripping spaces/hyphens and uppercasing).
     */
    [[nodiscard]] static std::string normalize_code(std::string_view code);

    /**
     * @brief Computes hex-encoded SHA-256 hash of a normalized recovery code.
     */
    [[nodiscard]] static std::string hash_code(std::string_view code);

    /**
     * @brief Verifies a user-presented code against an active hashed code pool in constant time.
     * @param raw_code User input (tolerates hyphens, spaces, and lowercase).
     * @param hashed_codes_pool List of remaining active hashed codes.
     * @return Index of the matched code in the pool to be consumed, or std::nullopt if invalid.
     */
    [[nodiscard]] static std::optional<size_t> verify_and_consume(std::string_view raw_code,
                                                                  const std::vector<std::string>& hashed_codes_pool);
};

} // namespace securecloud::auth::crypto
