#pragma once

#include <array>
#include <chrono>
#include <compare>
#include <cstdint>
#include <iomanip>
#include <openssl/rand.h>
#include <optional>
#include <pqxx/pqxx>
#include <sstream>
#include <string>
#include <string_view>

namespace securecloud::auth::domain {

/// RFC 9562-compliant, time-sortable 128-bit UUIDv7 value type.
class Uuid {
  public:
    using bytes_type = std::array<uint8_t, 16>;

    /// Default constructor creates a nil (all zeros) UUID.
    constexpr Uuid() noexcept : bytes_{} {}

    /// Construct from raw 16-byte array.
    constexpr explicit Uuid(const bytes_type& bytes) noexcept : bytes_(bytes) {}

    /// Generates a new cryptographically secure, time-ordered UUIDv7.
    [[nodiscard]] static Uuid generate_v7() {
        auto now_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());

        bytes_type bytes{};

        // 48-bit timestamp in big-endian order
        bytes[0] = static_cast<uint8_t>((now_ms >> 40) & 0xFF);
        bytes[1] = static_cast<uint8_t>((now_ms >> 32) & 0xFF);
        bytes[2] = static_cast<uint8_t>((now_ms >> 24) & 0xFF);
        bytes[3] = static_cast<uint8_t>((now_ms >> 16) & 0xFF);
        bytes[4] = static_cast<uint8_t>((now_ms >> 8) & 0xFF);
        bytes[5] = static_cast<uint8_t>(now_ms & 0xFF);

        // 10 random bytes
        std::array<uint8_t, 10> rand_bytes{};
        if (RAND_bytes(rand_bytes.data(), static_cast<int>(rand_bytes.size())) != 1) {
            throw std::runtime_error("OpenSSL RAND_bytes failed to generate entropy for UUIDv7");
        }

        // 4-bit version (7) + 12-bit rand_a
        bytes[6] = static_cast<uint8_t>(0x70 | (rand_bytes[0] & 0x0F));
        bytes[7] = rand_bytes[1];

        // 2-bit variant (10) + 62-bit rand_b
        bytes[8] = static_cast<uint8_t>(0x80 | (rand_bytes[2] & 0x3F));
        for (std::size_t i = 3; i < rand_bytes.size(); ++i) {
            bytes[6 + i] = rand_bytes[i];
        }

        return Uuid(bytes);
    }

    /// Parses a canonical 36-character hyphenated UUID string (case-insensitive).
    [[nodiscard]] static std::optional<Uuid> from_string(std::string_view str) noexcept {
        if (str.size() != 36) {
            return std::nullopt;
        }

        if (str[8] != '-' || str[13] != '-' || str[18] != '-' || str[23] != '-') {
            return std::nullopt;
        }

        auto hex_val = [](char c) noexcept -> int {
            if (c >= '0' && c <= '9') {
                return c - '0';
            }
            if (c >= 'a' && c <= 'f') {
                return c - 'a' + 10;
            }
            if (c >= 'A' && c <= 'F') {
                return c - 'A' + 10;
            }
            return -1;
        };

        bytes_type bytes{};
        std::size_t byte_idx = 0;
        for (std::size_t i = 0; i < 36;) {
            if (str[i] == '-') {
                ++i;
                continue;
            }
            int hi = hex_val(str[i]);
            int lo = hex_val(str[i + 1]);
            if (hi < 0 || lo < 0) {
                return std::nullopt;
            }
            bytes[byte_idx++] = static_cast<uint8_t>((hi << 4) | lo);
            i += 2;
        }

        return Uuid(bytes);
    }

    /// Formats as standard 36-character lowercase hyphenated string.
    [[nodiscard]] std::string to_string() const {
        static constexpr char hex_chars[] = "0123456789abcdef";
        std::string s(36, '-');
        auto write_byte = [&](std::size_t pos, uint8_t byte) {
            s[pos] = hex_chars[(byte >> 4) & 0x0F];
            s[pos + 1] = hex_chars[byte & 0x0F];
        };

        write_byte(0, bytes_[0]);
        write_byte(2, bytes_[1]);
        write_byte(4, bytes_[2]);
        write_byte(6, bytes_[3]);
        // '-' at 8
        write_byte(9, bytes_[4]);
        write_byte(11, bytes_[5]);
        // '-' at 13
        write_byte(14, bytes_[6]);
        write_byte(16, bytes_[7]);
        // '-' at 18
        write_byte(19, bytes_[8]);
        write_byte(21, bytes_[9]);
        // '-' at 23
        write_byte(24, bytes_[10]);
        write_byte(26, bytes_[11]);
        write_byte(28, bytes_[12]);
        write_byte(30, bytes_[13]);
        write_byte(32, bytes_[14]);
        write_byte(34, bytes_[15]);

        return s;
    }

    /// Access raw bytes.
    [[nodiscard]] constexpr const bytes_type& raw_bytes() const noexcept { return bytes_; }

    /// Returns the UUID version (should be 7 for v7).
    [[nodiscard]] constexpr uint8_t version() const noexcept { return static_cast<uint8_t>((bytes_[6] >> 4) & 0x0F); }

    /// Returns the UUID variant (should be 2 for RFC 4122 / 9562).
    [[nodiscard]] constexpr uint8_t variant() const noexcept {
        uint8_t v = static_cast<uint8_t>((bytes_[8] >> 6) & 0x03);
        return (v == 2 || v == 3) ? 2 : v;
    }

    /// Extracts timestamp in milliseconds from UUIDv7.
    [[nodiscard]] constexpr uint64_t timestamp_ms() const noexcept {
        return (static_cast<uint64_t>(bytes_[0]) << 40) | (static_cast<uint64_t>(bytes_[1]) << 32) |
               (static_cast<uint64_t>(bytes_[2]) << 24) | (static_cast<uint64_t>(bytes_[3]) << 16) |
               (static_cast<uint64_t>(bytes_[4]) << 8) | static_cast<uint64_t>(bytes_[5]);
    }

    /// Checks if nil UUID.
    [[nodiscard]] constexpr bool is_nil() const noexcept {
        for (uint8_t b : bytes_) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    constexpr explicit operator bool() const noexcept { return !is_nil(); }

    auto operator<=>(const Uuid&) const = default;
    bool operator==(const Uuid&) const = default;

  private:
    bytes_type bytes_{};
};

inline std::ostream& operator<<(std::ostream& os, const Uuid& id) {
    return os << id.to_string();
}

} // namespace securecloud::auth::domain

namespace std {
template <> struct hash<securecloud::auth::domain::Uuid> {
    std::size_t operator()(const securecloud::auth::domain::Uuid& id) const noexcept {
        const auto& b = id.raw_bytes();
        uint64_t hi = 0;
        uint64_t lo = 0;
        for (std::size_t i = 0; i < 8; ++i) {
            hi = (hi << 8) | b[i];
            lo = (lo << 8) | b[i + 8];
        }
        return static_cast<std::size_t>(hi ^ (lo * 0x9e3779b97f4a7c15ULL));
    }
};
} // namespace std

namespace pqxx {
template <> struct string_traits<securecloud::auth::domain::Uuid> {
    static constexpr bool converts_to_string = true;
    static constexpr bool converts_from_string = true;

    static zview to_buf(char* begin, char* end, const securecloud::auth::domain::Uuid& value) {
        if (end - begin < 37) {
            throw conversion_overrun("Buffer too small to format Uuid");
        }
        std::string str = value.to_string();
        std::copy(str.begin(), str.end(), begin);
        begin[36] = '\0';
        return zview(begin, 36);
    }

    static char* into_buf(char* begin, char* end, const securecloud::auth::domain::Uuid& value) {
        if (end - begin < 37) {
            throw conversion_overrun("Buffer too small to format Uuid");
        }
        std::string str = value.to_string();
        std::copy(str.begin(), str.end(), begin);
        begin[36] = '\0';
        return begin + 36;
    }

    static std::size_t size_buffer(const securecloud::auth::domain::Uuid&) noexcept { return 37; }

    static securecloud::auth::domain::Uuid from_string(std::string_view text) {
        auto parsed = securecloud::auth::domain::Uuid::from_string(text);
        if (!parsed) {
            throw conversion_error("Failed to parse Uuid from database string: " + std::string(text));
        }
        return *parsed;
    }
};
} // namespace pqxx
