#include "domain/user_profile.hpp"

#include <cctype>
#include <nlohmann/json.hpp>

namespace securecloud::client::domain {
namespace {

bool has_disallowed_single_line_control(std::string_view sv) noexcept {
    for (const char ch : sv) {
        const auto uch = static_cast<unsigned char>(ch);
        if (uch < 0x20U || uch == 0x7FU) {
            return true;
        }
    }
    return false;
}

bool has_disallowed_bio_control(std::string_view sv) noexcept {
    for (const char ch : sv) {
        const auto uch = static_cast<unsigned char>(ch);
        if ((uch < 0x20U && ch != '\n' && ch != '\t') || uch == 0x7FU) {
            return true;
        }
    }
    return false;
}

bool has_control_or_whitespace(std::string_view sv) noexcept {
    for (const char ch : sv) {
        const auto uch = static_cast<unsigned char>(ch);
        if (uch <= 0x20U || uch == 0x7FU) {
            return true;
        }
    }
    return false;
}

bool is_valid_public_handle_char(char ch) noexcept {
    const bool is_lower_alpha = (ch >= 'a' && ch <= 'z');
    const bool is_digit = (ch >= '0' && ch <= '9');
    return is_lower_alpha || is_digit || ch == '_' || ch == '.' || ch == '-';
}

bool starts_with_case_insensitive(std::string_view sv, std::string_view prefix) noexcept {
    if (sv.size() < prefix.size()) {
        return false;
    }
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        const auto a = static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(sv[i])));
        const auto b = static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(prefix[i])));
        if (a != b) {
            return false;
        }
    }
    return true;
}

bool is_plaintext_url_scheme(std::string_view value) noexcept {
    return starts_with_case_insensitive(value, "http://") || starts_with_case_insensitive(value, "https://") ||
           starts_with_case_insensitive(value, "file://") || starts_with_case_insensitive(value, "data:");
}

} // namespace

std::vector<std::string> UserProfile::validate() const {
    std::vector<std::string> errors;

    if (user_id.empty()) {
        errors.emplace_back("user_id cannot be empty");
    }

    if (!public_handle.empty()) {
        if (public_handle.size() < kMinPublicHandleLength || public_handle.size() > kMaxPublicHandleLength) {
            errors.emplace_back("public_handle must be between 3 and 64 characters when set");
        } else {
            for (const char ch : public_handle) {
                if (!is_valid_public_handle_char(ch)) {
                    errors.emplace_back("public_handle may only contain lowercase letters, digits, '_', '.', or '-'");
                    break;
                }
            }
        }
    }

    if (display_name.empty()) {
        errors.emplace_back("display_name cannot be empty");
    } else if (display_name.size() > kMaxDisplayNameBytes) {
        errors.emplace_back("display_name cannot exceed 128 bytes");
    } else if (has_disallowed_single_line_control(display_name)) {
        errors.emplace_back("display_name cannot contain ASCII control characters");
    }

    if (bio_status.size() > kMaxBioStatusBytes) {
        errors.emplace_back("bio_status cannot exceed 512 bytes");
    } else if (has_disallowed_bio_control(bio_status)) {
        errors.emplace_back("bio_status contains disallowed ASCII control characters");
    }

    if (!avatar_file_id.empty()) {
        if (avatar_file_id.size() > kMaxAvatarFileIdBytes || has_control_or_whitespace(avatar_file_id)) {
            errors.emplace_back("avatar_file_id must not contain whitespace/control characters or exceed 128 bytes");
        } else if (is_plaintext_url_scheme(avatar_file_id)) {
            errors.emplace_back("avatar_file_id must reference an encrypted Files object ID, never a plaintext URL");
        }
    }

    if (!avatar_sha256.empty() && !is_valid_sha256_hex(avatar_sha256)) {
        errors.emplace_back("avatar_sha256 must be empty or a valid 64-character hex SHA-256 digest");
    }

    if (updated_at_ms < 0) {
        errors.emplace_back("updated_at_ms must be non-negative");
    }

    return errors;
}

bool UserProfile::is_valid() const noexcept {
    return validate().empty();
}

std::string UserProfile::to_json() const {
    nlohmann::json root = nlohmann::json::object();
    root["user_id"] = user_id.value();
    root["public_handle"] = public_handle;
    root["display_name"] = display_name;
    root["bio_status"] = bio_status;
    root["avatar_file_id"] = avatar_file_id;
    root["avatar_sha256"] = normalize_hex_lower(avatar_sha256);
    root["allow_handle_discovery"] = allow_handle_discovery;
    root["updated_at_ms"] = updated_at_ms;
    return root.dump();
}

std::optional<UserProfile> UserProfile::from_json(std::string_view json_str) {
    const nlohmann::json j = nlohmann::json::parse(json_str.begin(), json_str.end(), nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        return std::nullopt;
    }

    UserProfile out;

    const auto uid_it = j.find("user_id");
    if (uid_it == j.end() || !uid_it->is_string()) {
        return std::nullopt;
    }
    std::string raw_user_id = uid_it->get<std::string>();
    if (raw_user_id.empty()) {
        return std::nullopt;
    }
    out.user_id = UserId(std::move(raw_user_id));

    if (const auto it = j.find("public_handle"); it != j.end()) {
        if (!it->is_string()) {
            return std::nullopt;
        }
        out.public_handle = it->get<std::string>();
    }

    const auto name_it = j.find("display_name");
    if (name_it == j.end() || !name_it->is_string()) {
        return std::nullopt;
    }
    out.display_name = name_it->get<std::string>();

    if (const auto it = j.find("bio_status"); it != j.end()) {
        if (!it->is_string()) {
            return std::nullopt;
        }
        out.bio_status = it->get<std::string>();
    }

    if (const auto it = j.find("avatar_file_id"); it != j.end()) {
        if (!it->is_string()) {
            return std::nullopt;
        }
        out.avatar_file_id = it->get<std::string>();
    }

    if (const auto it = j.find("avatar_sha256"); it != j.end()) {
        if (!it->is_string()) {
            return std::nullopt;
        }
        out.avatar_sha256 = normalize_hex_lower(it->get<std::string>());
    }

    if (const auto it = j.find("allow_handle_discovery"); it != j.end()) {
        if (!it->is_boolean()) {
            return std::nullopt;
        }
        out.allow_handle_discovery = it->get<bool>();
    }

    if (const auto it = j.find("updated_at_ms"); it != j.end()) {
        if (!it->is_number_integer()) {
            return std::nullopt;
        }
        out.updated_at_ms = it->get<int64_t>();
    }

    if (!out.is_valid()) {
        return std::nullopt;
    }
    return out;
}

} // namespace securecloud::client::domain
