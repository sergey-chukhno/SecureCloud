#pragma once

#include <cstddef>
#include <iosfwd>
#include <string>
#include <string_view>

namespace securecloud::common::configuration {

/// Best-effort secret handling wrapper designed to mitigate accidental leakage in logs,
/// stream output, validation diagnostics, and exceptions.
///
/// Guarantees:
/// - Stream output via operator<< prints "[REDACTED]".
/// - No implicit conversion to std::string, std::string_view, or const char*.
/// - Explicit retrieval requires calling .expose_unredacted_secret().
/// - Best-effort memory wipe upon destruction.
///
/// Non-Guarantees:
/// - Does NOT guarantee protection against core dumps, swap, attached debuggers, or SSO stack copies.
class SecretString final {
  public:
    SecretString() noexcept;
    explicit SecretString(std::string secret) noexcept;
    explicit SecretString(std::string_view secret);
    explicit SecretString(const char* secret);

    ~SecretString();

    SecretString(const SecretString& other);
    SecretString& operator=(const SecretString& other);

    SecretString(SecretString&& other) noexcept;
    SecretString& operator=(SecretString&& other) noexcept;

    [[nodiscard]] bool empty() const noexcept;
    [[nodiscard]] std::size_t size() const noexcept;

    /// Explicitly accesses the unredacted secret value.
    /// Lifetime of the returned reference is bound to this SecretString instance.
    [[nodiscard]] const std::string& expose_unredacted_secret() const noexcept;

    /// Friend stream operator outputting "[REDACTED]".
    friend std::ostream& operator<<(std::ostream& os, const SecretString& secret);

    bool operator==(const SecretString& other) const noexcept;
    bool operator!=(const SecretString& other) const noexcept;

  private:
    void wipe_buffer() noexcept;

    std::string m_secret;
};

} // namespace securecloud::common::configuration
