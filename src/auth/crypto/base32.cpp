#include "auth/crypto/base32.hpp"

#include <cctype>

namespace securecloud::auth::crypto {

namespace {

constexpr char kBase32Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

int base32_char_value(char c) noexcept {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a';
    }
    if (c >= '2' && c <= '7') {
        return c - '2' + 26;
    }
    return -1;
}

} // namespace

std::string Base32::encode(std::string_view data, bool include_padding) {
    return encode(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(data.data()), data.size()),
                  include_padding);
}

std::string Base32::encode(std::span<const uint8_t> data, bool include_padding) {
    std::string encoded;
    if (data.empty()) {
        return encoded;
    }

    // Every 5 bytes -> 8 Base32 chars
    encoded.reserve(((data.size() + 4) / 5) * 8);

    uint32_t buffer = 0;
    int bits_left = 0;

    for (const uint8_t byte : data) {
        buffer = (buffer << 8) | byte;
        bits_left += 8;

        while (bits_left >= 5) {
            bits_left -= 5;
            encoded.push_back(kBase32Alphabet[(buffer >> bits_left) & 0x1F]);
        }
    }

    if (bits_left > 0) {
        buffer <<= (5 - bits_left);
        encoded.push_back(kBase32Alphabet[buffer & 0x1F]);
    }

    if (include_padding) {
        while (encoded.size() % 8 != 0) {
            encoded.push_back('=');
        }
    }

    return encoded;
}

std::optional<std::vector<uint8_t>> Base32::decode(std::string_view input) {
    std::vector<uint8_t> output;
    if (input.empty()) {
        return output;
    }

    output.reserve((input.size() * 5) / 8);

    uint32_t buffer = 0;
    int bits_left = 0;
    bool padding_started = false;

    for (const char c : input) {
        // Skip whitespace and hyphens for user convenience
        if (std::isspace(static_cast<unsigned char>(c)) || c == '-') {
            continue;
        }

        if (c == '=') {
            padding_started = true;
            continue;
        }

        // Characters after padding are invalid
        if (padding_started) {
            return std::nullopt;
        }

        const int val = base32_char_value(c);
        if (val < 0) {
            return std::nullopt;
        }

        buffer = (buffer << 5) | static_cast<uint32_t>(val);
        bits_left += 5;

        if (bits_left >= 8) {
            bits_left -= 8;
            output.push_back(static_cast<uint8_t>((buffer >> bits_left) & 0xFF));
        }
    }

    // Residual unused bits must be zero per RFC 4648 §3.5
    if (bits_left > 0) {
        const uint32_t residual = buffer & ((1u << bits_left) - 1u);
        if (residual != 0) {
            return std::nullopt;
        }
    }

    return output;
}

std::optional<std::string> Base32::decode_string(std::string_view input) {
    auto bytes = decode(input);
    if (!bytes.has_value()) {
        return std::nullopt;
    }
    return std::string(reinterpret_cast<const char*>(bytes->data()), bytes->size());
}

} // namespace securecloud::auth::crypto
