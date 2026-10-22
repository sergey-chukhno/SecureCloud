#pragma once

#include <cctype>
#include <cstddef>
#include <optional>
#include <ostream>
#include <securecloud/configuration/secret_string.hpp>
#include <stdexcept>
#include <string>
#include <string_view>

namespace securecloud::auth::domain {

/// Exception thrown when a credential identifier or password violates domain validation invariants.
class InvalidCredentialException : public std::invalid_argument {
  public:
    explicit InvalidCredentialException(const std::string& message) : std::invalid_argument(message) {}
};

/// Strongly typed value object representing a validated and normalized credential identifier
/// (e.g., username or email address).
///
/// Security properties:
/// - Normalizes input: trims leading and trailing whitespace.
/// - Enforces length boundaries: [kMinLength (3) .. kMaxLength (255)].
/// - Disallows ASCII control characters (< 32, 127) to prevent log injection and delimiter confusion.
class CredentialIdentifier final {
  public:
    static constexpr std::size_t kMinLength = 3;
    static constexpr std::size_t kMaxLength = 255;

    /// Attempts to parse and normalize a credential identifier. Returns std::nullopt on validation failure.
    static std::optional<CredentialIdentifier> create(std::string_view raw) noexcept {
        auto trimmed = trim_whitespace(raw);
        if (trimmed.size() < kMinLength || trimmed.size() > kMaxLength) {
            return std::nullopt;
        }
        for (char ch : trimmed) {
            auto uc = static_cast<unsigned char>(ch);
            if (uc < 32 || uc == 127) {
                return std::nullopt; // Disallow control characters
            }
        }
        return CredentialIdentifier(trimmed, PrivateTag{});
    }

    /// Constructs a credential identifier or throws InvalidCredentialException if validation fails.
    explicit CredentialIdentifier(std::string_view raw) {
        auto trimmed = trim_whitespace(raw);
        if (trimmed.size() < kMinLength) {
            throw InvalidCredentialException("Credential identifier too short (minimum " + std::to_string(kMinLength) +
                                             " characters)");
        }
        if (trimmed.size() > kMaxLength) {
            throw InvalidCredentialException("Credential identifier too long (maximum " + std::to_string(kMaxLength) +
                                             " characters)");
        }
        for (char ch : trimmed) {
            auto uc = static_cast<unsigned char>(ch);
            if (uc < 32 || uc == 127) {
                throw InvalidCredentialException("Credential identifier contains invalid control characters");
            }
        }
        value_ = std::string(trimmed);
    }

    [[nodiscard]] const std::string& value() const noexcept { return value_; }

    [[nodiscard]] std::string_view view() const noexcept { return value_; }

    bool operator==(const CredentialIdentifier& other) const noexcept { return value_ == other.value_; }

    bool operator!=(const CredentialIdentifier& other) const noexcept { return !(*this == other); }

    friend std::ostream& operator<<(std::ostream& os, const CredentialIdentifier& id) { return os << id.value_; }

  private:
    struct PrivateTag {};
    CredentialIdentifier(std::string_view validated_str, PrivateTag) : value_(validated_str) {}

    static std::string_view trim_whitespace(std::string_view s) noexcept {
        while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n')) {
            s.remove_prefix(1);
        }
        while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n')) {
            s.remove_suffix(1);
        }
        return s;
    }

    std::string value_;
};

/// Strongly typed secure container wrapping a candidate password.
///
/// Security properties:
/// - Enforces maximum length of 1024 bytes to mitigate algorithmic complexity DoS attacks against Argon2id.
/// - Wraps data in SecretString, ensuring memory buffer is wiped with OPENSSL_cleanse on destruction.
/// - Overloads operator<< to emit "[REDACTED_PASSWORD]" guaranteeing zero accidental password logging.
class PasswordCredential final {
  public:
    static constexpr std::size_t kMaxLength = 1024;

    /// Attempts to construct a PasswordCredential. Returns std::nullopt if length exceeds kMaxLength.
    static std::optional<PasswordCredential> create(std::string_view raw) noexcept {
        if (raw.size() > kMaxLength) {
            return std::nullopt;
        }
        return PasswordCredential(common::configuration::SecretString(raw));
    }

    /// Constructs a PasswordCredential or throws InvalidCredentialException if length exceeds kMaxLength.
    explicit PasswordCredential(std::string_view raw) {
        if (raw.size() > kMaxLength) {
            throw InvalidCredentialException("Password exceeds maximum allowed length of " +
                                             std::to_string(kMaxLength) + " bytes");
        }
        secret_ = common::configuration::SecretString(raw);
    }

    explicit PasswordCredential(common::configuration::SecretString secret) : secret_(std::move(secret)) {
        if (secret_.size() > kMaxLength) {
            throw InvalidCredentialException("Password exceeds maximum allowed length of " +
                                             std::to_string(kMaxLength) + " bytes");
        }
    }

    ~PasswordCredential() = default;

    PasswordCredential(const PasswordCredential&) = default;
    PasswordCredential& operator=(const PasswordCredential&) = default;
    PasswordCredential(PasswordCredential&&) noexcept = default;
    PasswordCredential& operator=(PasswordCredential&&) noexcept = default;

    [[nodiscard]] const common::configuration::SecretString& secret() const noexcept { return secret_; }

    [[nodiscard]] std::size_t size() const noexcept { return secret_.size(); }

    [[nodiscard]] bool empty() const noexcept { return secret_.empty(); }

    /// Redacts password representation in standard streams to prevent inadvertent disclosure in logs.
    friend std::ostream& operator<<(std::ostream& os, const PasswordCredential& /*pwd*/) {
        return os << "[REDACTED_PASSWORD]";
    }

  private:
    common::configuration::SecretString secret_;
};

} // namespace securecloud::auth::domain
