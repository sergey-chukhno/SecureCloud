#pragma once

#include <array>
#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace securecloud::audit::domain {

/// Strongly-typed value object representing an RFC 9562 UUIDv7 identifier.
class EventId {
  public:
    using bytes_type = std::array<uint8_t, 16>;

    constexpr EventId() noexcept = default;
    constexpr explicit EventId(const bytes_type& bytes) noexcept : bytes_(bytes) {}

    /// Generates a cryptographically strong RFC 9562 UUIDv7 using OpenSSL RAND_bytes.
    [[nodiscard]] static EventId generate_v7();

    /// Parses a 36-character canonical UUID string (8-4-4-4-12).
    /// Returns std::nullopt if string is malformed or not a valid UUIDv7 (variant 10xx).
    [[nodiscard]] static std::optional<EventId> from_string(std::string_view sv) noexcept;

    /// Formats as 36-character lowercase canonical UUID string.
    [[nodiscard]] std::string to_string() const;

    [[nodiscard]] constexpr const bytes_type& bytes() const noexcept { return bytes_; }
    [[nodiscard]] constexpr bool is_nil() const noexcept { return bytes_ == bytes_type{}; }

    /// Extract 4-bit UUID version (must be 7 for RFC 9562 UUIDv7).
    [[nodiscard]] uint8_t version() const noexcept { return static_cast<uint8_t>((bytes_[6] >> 4) & 0x0F); }

    /// Extract 2-bit RFC 4122/9562 variant (must be 2, corresponding to binary 10xx).
    [[nodiscard]] uint8_t variant() const noexcept { return static_cast<uint8_t>((bytes_[8] >> 6) & 0x03); }

    /// Extract embedded 48-bit millisecond timestamp.
    [[nodiscard]] uint64_t timestamp_ms() const noexcept;

    constexpr auto operator<=>(const EventId& other) const noexcept = default;
    constexpr bool operator==(const EventId& other) const noexcept = default;

  private:
    bytes_type bytes_{};
};

} // namespace securecloud::audit::domain