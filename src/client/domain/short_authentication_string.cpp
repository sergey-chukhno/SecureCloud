#include "domain/short_authentication_string.hpp"

#include <algorithm>
#include <iomanip>
#include <openssl/evp.h>
#include <sstream>

namespace securecloud::client::domain {

namespace {

// 64 cross-platform universally recognized emojis without skin-tones or vendor ambiguities
constexpr std::array<std::string_view, ShortAuthenticationString::kDictionarySize> kEmojiDictionary = {
    "🚀", "🛡️",  "🔑", "⚡", "🌟", "🔥", "💎", "🎯", "⚓", "🪐", "🍀", "🌊", "🔔", "🎸", "🏆", "🧭",
    "🎨", "📚", "🔮", "💡", "📡", "🧩", "🦄", "🦅", "🦁", "🐬", "🌸", "🍁", "🍄", "🌴", "🌲", "🍎",
    "☕", "🚗", "✈️",  "⛵", "🏰", "🏔️",  "🌈", "☀️",  "🌙", "⭐", "🔒", "🔓", "🔍", "⚙️",  "🔧", "📦",
    "🏷️",  "📷", "🎙️",  "🎧", "🕹️",  "⏰", "⌛", "🎁", "🎈", "🎉", "💌", "📬", "📜", "🪙", "👑", "🕊️"};

} // namespace

ShortAuthenticationString::ShortAuthenticationString(std::string numeric_code,
                                                     std::array<std::string, kEmojiCount> visual_emojis)
    : numeric_code_(std::move(numeric_code)), visual_emojis_(std::move(visual_emojis)) {}

ShortAuthenticationString ShortAuthenticationString::from_handshake_material(std::span<const uint8_t> primary_key,
                                                                             std::span<const uint8_t> companion_key,
                                                                             std::string_view pairing_code) {
    // Canonicalize key ordering so derivation is order-independent
    std::span<const uint8_t> first_key = primary_key;
    std::span<const uint8_t> second_key = companion_key;
    if (std::lexicographical_compare(companion_key.begin(), companion_key.end(), primary_key.begin(),
                                     primary_key.end())) {
        std::swap(first_key, second_key);
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return ShortAuthenticationString();
    }

    std::array<uint8_t, 32> digest{};
    unsigned int md_len = 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, first_key.data(), first_key.size()) != 1 ||
        EVP_DigestUpdate(ctx, second_key.data(), second_key.size()) != 1 ||
        EVP_DigestUpdate(ctx, pairing_code.data(), pairing_code.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, digest.data(), &md_len) != 1 || md_len != 32) {
        EVP_MD_CTX_free(ctx);
        return ShortAuthenticationString();
    }
    EVP_MD_CTX_free(ctx);

    // Derive 6-digit decimal code (000000..999999) from first 4 bytes
    uint32_t val = (static_cast<uint32_t>(digest[0]) << 24) | (static_cast<uint32_t>(digest[1]) << 16) |
                   (static_cast<uint32_t>(digest[2]) << 8) | (static_cast<uint32_t>(digest[3]));
    val %= 1000000;

    std::ostringstream oss;
    oss << std::setw(6) << std::setfill('0') << val;
    std::string num_code = oss.str();

    // Derive 4 visual emojis from next 4 bytes
    std::array<std::string, kEmojiCount> emojis{
        std::string(kEmojiDictionary[digest[4] % kDictionarySize]),
        std::string(kEmojiDictionary[digest[5] % kDictionarySize]),
        std::string(kEmojiDictionary[digest[6] % kDictionarySize]),
        std::string(kEmojiDictionary[digest[7] % kDictionarySize]),
    };

    return ShortAuthenticationString(std::move(num_code), std::move(emojis));
}

std::string ShortAuthenticationString::formatted_code() const {
    if (numeric_code_.size() == 6) {
        return numeric_code_.substr(0, 3) + " " + numeric_code_.substr(3, 3);
    }
    return numeric_code_;
}

std::string ShortAuthenticationString::formatted_emojis() const {
    std::ostringstream oss;
    for (std::size_t i = 0; i < visual_emojis_.size(); ++i) {
        if (i > 0) {
            oss << " ";
        }
        oss << visual_emojis_[i];
    }
    return oss.str();
}

std::string ShortAuthenticationString::formatted_text() const {
    return formatted_code() + " [" + formatted_emojis() + "]";
}

bool ShortAuthenticationString::operator==(const ShortAuthenticationString& other) const noexcept {
    return numeric_code_ == other.numeric_code_ && visual_emojis_ == other.visual_emojis_;
}

} // namespace securecloud::client::domain
