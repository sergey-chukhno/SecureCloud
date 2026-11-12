#pragma once

#include <array>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::domain {

class ShortAuthenticationString {
  public:
    static constexpr std::size_t kEmojiCount = 4;
    static constexpr std::size_t kDictionarySize = 64;

    ShortAuthenticationString() = default;

    ShortAuthenticationString(std::string numeric_code, std::array<std::string, kEmojiCount> visual_emojis);

    static ShortAuthenticationString from_handshake_material(std::span<const uint8_t> primary_key,
                                                             std::span<const uint8_t> companion_key,
                                                             std::string_view pairing_code);

    [[nodiscard]] const std::string& numeric_code() const noexcept { return numeric_code_; }
    [[nodiscard]] const std::array<std::string, kEmojiCount>& visual_emojis() const noexcept { return visual_emojis_; }

    [[nodiscard]] std::string formatted_code() const;
    [[nodiscard]] std::string formatted_emojis() const;
    [[nodiscard]] std::string formatted_text() const;

    bool operator==(const ShortAuthenticationString& other) const noexcept;
    bool operator!=(const ShortAuthenticationString& other) const noexcept { return !(*this == other); }

  private:
    std::string numeric_code_{"000000"};
    std::array<std::string, kEmojiCount> visual_emojis_{"🚀", "🛡️", "🔑", "⚡"};
};

} // namespace securecloud::client::domain
