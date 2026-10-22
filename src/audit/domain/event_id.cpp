#include "event_id.hpp"

#include <openssl/rand.h>

#include <chrono>
#include <cstdio>
#include <stdexcept>

namespace securecloud::audit::domain {

namespace {

int hex_digit_to_int(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

} // namespace

EventId EventId::generate_v7() {
    bytes_type raw{};
    if (RAND_bytes(raw.data(), static_cast<int>(raw.size())) != 1) {
        throw std::runtime_error("OpenSSL RAND_bytes failed during UUIDv7 generation");
    }

    auto now_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());

    // 48-bit big-endian millisecond timestamp into bytes 0..5
    raw[0] = static_cast<uint8_t>((now_ms >> 40) & 0xFF);
    raw[1] = static_cast<uint8_t>((now_ms >> 32) & 0xFF);
    raw[2] = static_cast<uint8_t>((now_ms >> 24) & 0xFF);
    raw[3] = static_cast<uint8_t>((now_ms >> 16) & 0xFF);
    raw[4] = static_cast<uint8_t>((now_ms >> 8) & 0xFF);
    raw[5] = static_cast<uint8_t>(now_ms & 0xFF);

    // Set UUIDv7 version (0b0111) in top 4 bits of byte 6
    raw[6] = static_cast<uint8_t>((raw[6] & 0x0F) | 0x70);

    // Set RFC 4122 / RFC 9562 variant (0b10xx) in top 2 bits of byte 8
    raw[8] = static_cast<uint8_t>((raw[8] & 0x3F) | 0x80);

    return EventId(raw);
}

std::optional<EventId> EventId::from_string(std::string_view sv) noexcept {
    if (sv.size() != 36) {
        return std::nullopt;
    }

    if (sv[8] != '-' || sv[13] != '-' || sv[18] != '-' || sv[23] != '-') {
        return std::nullopt;
    }

    bytes_type raw{};
    size_t byte_idx = 0;

    for (size_t i = 0; i < sv.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            continue;
        }

        int hi = hex_digit_to_int(sv[i]);
        int lo = hex_digit_to_int(sv[++i]);

        if (hi < 0 || lo < 0) {
            return std::nullopt;
        }

        raw[byte_idx++] = static_cast<uint8_t>((hi << 4) | lo);
    }

    EventId id(raw);

    // Enforce version 7 and variant 2 (10xx in binary)
    if (id.version() != 7 || id.variant() != 2) {
        return std::nullopt;
    }

    return id;
}

std::string EventId::to_string() const {
    char buf[37];
    std::snprintf(
        buf, sizeof(buf),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes_[0], bytes_[1], bytes_[2], bytes_[3],
        bytes_[4], bytes_[5],
        bytes_[6], bytes_[7],
        bytes_[8], bytes_[9],
        bytes_[10], bytes_[11], bytes_[12], bytes_[13], bytes_[14], bytes_[15]);
    return std::string(buf, 36);
}

uint64_t EventId::timestamp_ms() const noexcept {
    return (static_cast<uint64_t>(bytes_[0]) << 40) |
           (static_cast<uint64_t>(bytes_[1]) << 32) |
           (static_cast<uint64_t>(bytes_[2]) << 24) |
           (static_cast<uint64_t>(bytes_[3]) << 16) |
           (static_cast<uint64_t>(bytes_[4]) << 8)  |
           (static_cast<uint64_t>(bytes_[5]));
}

} // namespace securecloud::audit::domain
