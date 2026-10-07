#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::auth::crypto {

/**
 * @brief Supported HMAC hash algorithms for TOTP per RFC 6238.
 */
enum class TotpHashAlgorithm {
    Sha1,   ///< RFC 6238 default, universally supported by Google Authenticator / 1Password
    Sha256  ///< Higher collision resistance
};

/**
 * @brief Configuration parameters for TOTP generation and verification.
 */
struct TotpConfig {
    uint32_t digits = 6;
    uint32_t time_step_seconds = 30;
    TotpHashAlgorithm algorithm = TotpHashAlgorithm::Sha1;
    int drift_window_steps = 1; ///< +/- 1 step allows [T-1, T+1] (90 seconds total validity window)
};

/**
 * @brief Result of a TOTP verification operation.
 */
struct TotpVerificationResult {
    bool is_valid = false;
    uint64_t matched_time_step = 0; ///< Time-step counter (T = epoch / 30) that satisfied the verification
};

/**
 * @brief RFC 6238 Time-based One-Time Password (TOTP) engine.
 *
 * Provides cryptographic generation of 160-bit shared secrets, calculation of 6-digit codes
 * via HMAC-SHA1/SHA256 and dynamic truncation (RFC 4226), constant-time verification over
 * a drift tolerance window (+/- 1 step), and generation of standard otpauth:// URIs.
 */
class TotpEngine {
  public:
    explicit TotpEngine(TotpConfig config = {});

    /**
     * @brief Generates cryptographically secure random bytes for a TOTP shared secret.
     * @param num_bytes Length in bytes (default 20 bytes = 160 bits per RFC 6238 recommendations).
     * @return Vector of securely generated random bytes.
     */
    [[nodiscard]] static std::vector<uint8_t> generate_secret_bytes(size_t num_bytes = 20);

    /**
     * @brief Computes the TOTP code for a given timestamp.
     * @param secret Raw secret bytes.
     * @param timestamp_seconds Unix epoch timestamp in seconds.
     * @return Zero-padded 6-digit (or configured digit count) numeric code string.
     */
    [[nodiscard]] std::string compute_code(std::span<const uint8_t> secret, uint64_t timestamp_seconds) const;

    /**
     * @brief Verifies a user-presented TOTP code against the secret over the drift window.
     *
     * Evaluates steps in [T - window, T + window] using constant-time string comparisons.
     *
     * @param secret Raw secret bytes.
     * @param code User-presented 6-digit code.
     * @param timestamp_seconds Current Unix epoch timestamp in seconds.
     * @return Verification result indicating validity and the matched time step.
     */
    [[nodiscard]] TotpVerificationResult verify_code(std::span<const uint8_t> secret,
                                                    std::string_view code,
                                                    uint64_t timestamp_seconds) const;

    /**
     * @brief Formats a standard otpauth:// URI for rendering as a QR code in client authenticators.
     * @param issuer Service name (e.g., "SecureCloud").
     * @param account_name User identifier or email (e.g., "alice@example.com").
     * @param base32_secret Base32-encoded secret string.
     * @return Fully formatted and URL-encoded otpauth://totp/ URI.
     */
    [[nodiscard]] std::string generate_otpauth_uri(std::string_view issuer,
                                                  std::string_view account_name,
                                                  std::string_view base32_secret) const;

    [[nodiscard]] const TotpConfig& config() const noexcept { return config_; }

  private:
    TotpConfig config_;
};

} // namespace securecloud::auth::crypto
