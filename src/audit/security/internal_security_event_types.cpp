#include "security/internal_security_event_types.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <string>

namespace securecloud::audit::security {

    namespace {

        constexpr std::array<std::string_view, 5> kProhibitedKeySubstrings = {
            "token", "auth", "password", "key", "secret"
        };

        std::string to_lower(std::string_view sv) {
            std::string result;
            result.reserve(sv.size());
            for (char c : sv) {
                result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            }
            return result;
        }

    } // namespace

    bool is_prohibited_metadata_key(std::string_view key) noexcept {
        std::string lower_key = to_lower(key);
        for (std::string_view prohibited : kProhibitedKeySubstrings) {
            if (lower_key.find(prohibited) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    bool validate_internal_metadata_key_value(std::string_view key, std::string_view value) noexcept {
        if (key.empty() || key.size() > kMaxInternalMetadataKeyLength) {
            return false;
        }
        if (value.size() > kMaxInternalMetadataValueLength) {
            return false;
        }
        if (is_prohibited_metadata_key(key)) {
            return false;
        }
        return true;
    }

    bool validate_internal_metadata(const std::unordered_map<std::string, std::string>& metadata) noexcept {
        if (metadata.size() > kMaxInternalMetadataPairs) {
            return false;
        }
        for (const auto& [k, v] : metadata) {
            if (!validate_internal_metadata_key_value(k, v)) {
                return false;
            }
        }
        return true;
    }

} // namespace securecloud::audit::security