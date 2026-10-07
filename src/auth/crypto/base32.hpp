#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::auth::crypto {

/**
 * @brief RFC 4648 standard Base32 encoder and decoder.
 *
 * Implements Base32 encoding with standard alphabet: 'A'-'Z', '2'-'7'.
 * Decoder provides human-error tolerance (case-insensitivity, whitespace/hyphen stripping)
 * and strict character set validation.
 */
class Base32 {
  public:
    /**
     * @brief Encodes binary data into an RFC 4648 Base32 string.
     * @param data Raw binary bytes.
     * @param include_padding Whether to append '=' padding characters.
     * @return Uppercase Base32 encoded string.
     */
    [[nodiscard]] static std::string encode(std::span<const uint8_t> data, bool include_padding = false);

    /**
     * @brief Convenience overload encoding string_view input.
     */
    [[nodiscard]] static std::string encode(std::string_view data, bool include_padding = false);

    /**
     * @brief Decodes an RFC 4648 Base32 string into raw bytes.
     *
     * Ignores whitespace and hyphens. Accepts both uppercase and lowercase characters.
     * Returns std::nullopt if the input contains invalid characters or malformed padding.
     *
     * @param input Base32 encoded string.
     * @return Decoded binary bytes or std::nullopt on error.
     */
    [[nodiscard]] static std::optional<std::vector<uint8_t>> decode(std::string_view input);

    /**
     * @brief Decodes an RFC 4648 Base32 string and returns as std::string.
     */
    [[nodiscard]] static std::optional<std::string> decode_string(std::string_view input);
};

} // namespace securecloud::auth::crypto
