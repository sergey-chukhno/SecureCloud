#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace securecloud::auth::crypto {

/**
 * @brief Cryptographic validation engine for batches of One-Time Prekeys (OTKs).
 *
 * Enforces:
 * - Batch size limits: [kMinBatchSize, kMaxBatchSize]
 * - Exact 32-byte X25519 public key length
 * - Rejection of all-zero and all-0xFF weak/degenerate points
 * - Intra-batch duplicate prevention
 * - Zero Private Key Invariant
 */
class PrekeyValidator {
  public:
    static constexpr std::size_t kX25519KeySize = 32;
    static constexpr std::size_t kMinBatchSize = 1;
    static constexpr std::size_t kMaxBatchSize = 100;

    /**
     * @brief Validates a single 32-byte X25519 one-time prekey.
     */
    [[nodiscard]] static bool validate_single_prekey(std::span<const uint8_t> key_bytes,
                                                     std::string* error_out = nullptr);

    /**
     * @brief Validates a batch of one-time prekeys.
     * Enforces size boundaries [1, 100], validity of each key, and no duplicate keys in the batch.
     */
    [[nodiscard]] static bool validate_prekey_batch(const std::vector<std::vector<uint8_t>>& prekeys,
                                                    std::string* error_out = nullptr);
};

} // namespace securecloud::auth::crypto
