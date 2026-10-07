#pragma once

#include <cstdint>
#include <iostream>
#include <openssl/crypto.h>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace securecloud::auth::domain {

/**
 * @brief RAII memory-scrubbing wrapper for sensitive MFA secrets and verification codes.
 *
 * Prevents accidental disclosure in stdout, log files, stack traces, and debug streams
 * by overloading operator<< to emit "[REDACTED_MFA_SECRET]".
 * Securely scrubs internal memory via OPENSSL_cleanse upon destruction.
 */
class SecretMfaString {
  public:
    SecretMfaString() = default;

    explicit SecretMfaString(std::string secret) : secret_(std::move(secret)) {}

    explicit SecretMfaString(std::span<const uint8_t> bytes)
        : secret_(reinterpret_cast<const char*>(bytes.data()), bytes.size()) {}

    explicit SecretMfaString(const std::vector<uint8_t>& bytes)
        : secret_(reinterpret_cast<const char*>(bytes.data()), bytes.size()) {}

    ~SecretMfaString() {
        if (!secret_.empty()) {
            OPENSSL_cleanse(secret_.data(), secret_.size());
        }
    }

    SecretMfaString(const SecretMfaString& other) : secret_(other.secret_) {}

    SecretMfaString& operator=(const SecretMfaString& other) {
        if (this != &other) {
            if (!secret_.empty()) {
                OPENSSL_cleanse(secret_.data(), secret_.size());
            }
            secret_ = other.secret_;
        }
        return *this;
    }

    SecretMfaString(SecretMfaString&& other) noexcept : secret_(std::move(other.secret_)) {
        // other.secret_ is now moved-from (usually empty in libc++)
    }

    SecretMfaString& operator=(SecretMfaString&& other) noexcept {
        if (this != &other) {
            if (!secret_.empty()) {
                OPENSSL_cleanse(secret_.data(), secret_.size());
            }
            secret_ = std::move(other.secret_);
        }
        return *this;
    }

    [[nodiscard]] const std::string& raw_secret() const noexcept { return secret_; }
    [[nodiscard]] std::string_view raw_view() const noexcept { return secret_; }

    [[nodiscard]] std::span<const uint8_t> as_bytes() const noexcept {
        return std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(secret_.data()), secret_.size());
    }

    [[nodiscard]] bool empty() const noexcept { return secret_.empty(); }
    [[nodiscard]] size_t size() const noexcept { return secret_.size(); }

    bool operator==(const SecretMfaString& other) const noexcept {
        if (secret_.size() != other.secret_.size()) {
            return false;
        }
        return CRYPTO_memcmp(secret_.data(), other.secret_.data(), secret_.size()) == 0;
    }

    bool operator!=(const SecretMfaString& other) const noexcept { return !(*this == other); }

    friend std::ostream& operator<<(std::ostream& os, const SecretMfaString& /*secret*/) {
        return os << "[REDACTED_MFA_SECRET]";
    }

  private:
    std::string secret_{};
};

} // namespace securecloud::auth::domain
