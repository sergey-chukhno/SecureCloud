#pragma once

#include <array>
#include <chrono>
#include <compare>
#include <cstdint>
#include <iomanip>
#include <openssl/rand.h>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace securecloud::messaging::domain {

/// Topology classification of a conversation.
enum class ConversationType : uint8_t {
    Direct = 1,
    Group = 2,
};

/// Operational status of a group conversation.
enum class GroupStatus : uint8_t {
    Active = 1,
    Closed = 2,
};

/// Membership standing of a participant within a conversation.
enum class MembershipStatus : uint8_t {
    Active = 1,
    Left = 2,
    Removed = 3,
};

/// Granular role of a participant within a conversation.
enum class ParticipantRole : uint8_t {
    Member = 1,
    Admin = 2,
};

/// Strongly-typed RFC 9562 UUIDv7 value object for Conversation identifiers.
class ConversationId {
  public:
    using bytes_type = std::array<uint8_t, 16>;

    constexpr ConversationId() noexcept : bytes_{} {}
    constexpr explicit ConversationId(const bytes_type& bytes) noexcept : bytes_(bytes) {}

    [[nodiscard]] static ConversationId generate_v7() {
        auto now_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());

        bytes_type bytes{};
        bytes[0] = static_cast<uint8_t>((now_ms >> 40) & 0xFF);
        bytes[1] = static_cast<uint8_t>((now_ms >> 32) & 0xFF);
        bytes[2] = static_cast<uint8_t>((now_ms >> 24) & 0xFF);
        bytes[3] = static_cast<uint8_t>((now_ms >> 16) & 0xFF);
        bytes[4] = static_cast<uint8_t>((now_ms >> 8) & 0xFF);
        bytes[5] = static_cast<uint8_t>(now_ms & 0xFF);

        std::array<uint8_t, 10> rand_bytes{};
        if (RAND_bytes(rand_bytes.data(), static_cast<int>(rand_bytes.size())) != 1) {
            throw std::runtime_error("OpenSSL RAND_bytes failed to generate entropy for ConversationId UUIDv7");
        }

        bytes[6] = static_cast<uint8_t>(0x70 | (rand_bytes[0] & 0x0F));
        bytes[7] = rand_bytes[1];
        bytes[8] = static_cast<uint8_t>(0x80 | (rand_bytes[2] & 0x3F));
        for (std::size_t i = 3; i < rand_bytes.size(); ++i) {
            bytes[6 + i] = rand_bytes[i];
        }

        return ConversationId(bytes);
    }

    [[nodiscard]] static std::optional<ConversationId> from_string(std::string_view sv) noexcept {
        if (sv.size() != 36) {
            return std::nullopt;
        }
        if (sv[8] != '-' || sv[13] != '-' || sv[18] != '-' || sv[23] != '-') {
            return std::nullopt;
        }

        auto hex_val = [](char c) -> int {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            return -1;
        };

        bytes_type bytes{};
        std::size_t byte_idx = 0;
        for (std::size_t i = 0; i < 36;) {
            if (i == 8 || i == 13 || i == 18 || i == 23) {
                ++i;
                continue;
            }
            int hi = hex_val(sv[i]);
            int lo = hex_val(sv[i + 1]);
            if (hi < 0 || lo < 0) {
                return std::nullopt;
            }
            bytes[byte_idx++] = static_cast<uint8_t>((hi << 4) | lo);
            i += 2;
        }
        return ConversationId(bytes);
    }

    [[nodiscard]] std::string to_string() const {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (std::size_t i = 0; i < 16; ++i) {
            if (i == 4 || i == 6 || i == 8 || i == 10) {
                oss << '-';
            }
            oss << std::setw(2) << static_cast<int>(bytes_[i]);
        }
        return oss.str();
    }

    [[nodiscard]] constexpr const bytes_type& bytes() const noexcept { return bytes_; }
    [[nodiscard]] constexpr bool is_nil() const noexcept { return bytes_ == bytes_type{}; }

    constexpr auto operator<=>(const ConversationId& other) const noexcept = default;
    constexpr bool operator==(const ConversationId& other) const noexcept = default;

  private:
    bytes_type bytes_{};
};

/// Strongly-typed User identifier value object.
class UserId {
  public:
    UserId() = default;
    explicit UserId(std::string id) : id_(std::move(id)) {}

    [[nodiscard]] static bool is_valid_format(std::string_view sv) noexcept {
        if (sv.size() != 36)
            return false;
        if (sv[8] != '-' || sv[13] != '-' || sv[18] != '-' || sv[23] != '-')
            return false;
        for (std::size_t i = 0; i < 36; ++i) {
            if (i == 8 || i == 13 || i == 18 || i == 23)
                continue;
            char c = sv[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] static std::optional<UserId> from_string(std::string_view sv) noexcept {
        if (!is_valid_format(sv)) {
            return std::nullopt;
        }
        return UserId(std::string(sv));
    }

    [[nodiscard]] const std::string& str() const noexcept { return id_; }
    [[nodiscard]] bool empty() const noexcept { return id_.empty(); }

    auto operator<=>(const UserId& other) const noexcept = default;
    bool operator==(const UserId& other) const noexcept = default;

  private:
    std::string id_{};
};

/// Canonical lexicographical user pair (user_a, user_b) for direct conversations.
/// Invariant: user_a < user_b.
class DirectPair {
  public:
    DirectPair(UserId first, UserId second) {
        if (first == second) {
            throw std::invalid_argument("Direct conversation cannot be created with identical users");
        }
        if (first < second) {
            user_a_ = std::move(first);
            user_b_ = std::move(second);
        } else {
            user_a_ = std::move(second);
            user_b_ = std::move(first);
        }
    }

    [[nodiscard]] const UserId& user_a() const noexcept { return user_a_; }
    [[nodiscard]] const UserId& user_b() const noexcept { return user_b_; }

    auto operator<=>(const DirectPair& other) const noexcept = default;
    bool operator==(const DirectPair& other) const noexcept = default;

  private:
    UserId user_a_;
    UserId user_b_;
};

} // namespace securecloud::messaging::domain

namespace std {
template <> struct hash<securecloud::messaging::domain::ConversationId> {
    std::size_t operator()(const securecloud::messaging::domain::ConversationId& id) const noexcept {
        std::size_t seed = 0;
        for (uint8_t b : id.bytes()) {
            seed ^= std::hash<uint8_t>{}(b) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        }
        return seed;
    }
};

template <> struct hash<securecloud::messaging::domain::UserId> {
    std::size_t operator()(const securecloud::messaging::domain::UserId& uid) const noexcept {
        return std::hash<std::string>{}(uid.str());
    }
};

template <> struct hash<securecloud::messaging::domain::DirectPair> {
    std::size_t operator()(const securecloud::messaging::domain::DirectPair& pair) const noexcept {
        std::size_t h1 = std::hash<securecloud::messaging::domain::UserId>{}(pair.user_a());
        std::size_t h2 = std::hash<securecloud::messaging::domain::UserId>{}(pair.user_b());
        return h1 ^ (h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2));
    }
};
} // namespace std
