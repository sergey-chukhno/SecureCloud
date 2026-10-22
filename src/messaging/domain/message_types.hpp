#pragma once

#include "domain/conversation_types.hpp"

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
#include <vector>

namespace securecloud::messaging::domain {

/// Operational and delivery priority for a message.
enum class MessagePriority : uint8_t {
    Normal = 1,
    Urgent = 2,
    Emergency = 3,
};

[[nodiscard]] inline std::string to_string(MessagePriority priority) {
    switch (priority) {
    case MessagePriority::Normal:
        return "NORMAL";
    case MessagePriority::Urgent:
        return "URGENT";
    case MessagePriority::Emergency:
        return "EMERGENCY";
    }
    return "NORMAL";
}

[[nodiscard]] inline std::optional<MessagePriority> message_priority_from_string(std::string_view sv) noexcept {
    if (sv == "NORMAL") {
        return MessagePriority::Normal;
    }
    if (sv == "URGENT") {
        return MessagePriority::Urgent;
    }
    if (sv == "EMERGENCY") {
        return MessagePriority::Emergency;
    }
    return std::nullopt;
}

/// Strongly-typed Device identifier value object.
class DeviceId {
  public:
    DeviceId() = default;
    explicit DeviceId(std::string id) : id_(std::move(id)) {}

    [[nodiscard]] const std::string& str() const noexcept { return id_; }
    [[nodiscard]] const std::string& value() const noexcept { return id_; }
    [[nodiscard]] bool empty() const noexcept { return id_.empty(); }

    auto operator<=>(const DeviceId& other) const noexcept = default;
    bool operator==(const DeviceId& other) const noexcept = default;

  private:
    std::string id_;
};

/// Strongly-typed RFC 9562 UUIDv7 value object for Message identifiers.
class MessageId {
  public:
    using bytes_type = std::array<uint8_t, 16>;

    constexpr MessageId() noexcept : bytes_{} {}
    constexpr explicit MessageId(const bytes_type& bytes) noexcept : bytes_(bytes) {}

    [[nodiscard]] static MessageId generate_v7() {
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
            throw std::runtime_error("OpenSSL RAND_bytes failed to generate entropy for MessageId UUIDv7");
        }

        bytes[6] = static_cast<uint8_t>(0x70 | (rand_bytes[0] & 0x0F));
        bytes[7] = rand_bytes[1];
        bytes[8] = static_cast<uint8_t>(0x80 | (rand_bytes[2] & 0x3F));
        for (std::size_t i = 3; i < rand_bytes.size(); ++i) {
            bytes[6 + i] = rand_bytes[i];
        }

        return MessageId(bytes);
    }

    [[nodiscard]] static std::optional<MessageId> from_string(std::string_view sv) noexcept {
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
        return MessageId(bytes);
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

    constexpr auto operator<=>(const MessageId& other) const noexcept = default;
    constexpr bool operator==(const MessageId& other) const noexcept = default;

  private:
    bytes_type bytes_{};
};

/// Monotonically increasing per-conversation sequence number.
using MessageSequence = uint64_t;

/// Opaque end-to-end encrypted envelope containing message ciphertext.
struct CiphertextEnvelope {
    std::string ciphertext;
    int32_t envelope_version{1};

    auto operator<=>(const CiphertextEnvelope& other) const noexcept = default;
    bool operator==(const CiphertextEnvelope& other) const noexcept = default;
};

} // namespace securecloud::messaging::domain

namespace std {
template <> struct hash<securecloud::messaging::domain::DeviceId> {
    std::size_t operator()(const securecloud::messaging::domain::DeviceId& id) const noexcept {
        return std::hash<std::string>{}(id.str());
    }
};

template <> struct hash<securecloud::messaging::domain::MessageId> {
    std::size_t operator()(const securecloud::messaging::domain::MessageId& id) const noexcept {
        std::string_view sv(reinterpret_cast<const char*>(id.bytes().data()), id.bytes().size());
        return std::hash<std::string_view>{}(sv);
    }
};
} // namespace std
