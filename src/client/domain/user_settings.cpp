#include "domain/user_settings.hpp"

#include <cctype>
#include <cmath>
#include <limits>
#include <nlohmann/json.hpp>

namespace securecloud::client::domain {
namespace {

constexpr std::size_t kMaxHostOrUserBytes = 255U;

std::string to_lower_ascii(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    for (const char ch : sv) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return out;
}

bool contains_ascii_control_or_whitespace(std::string_view sv) noexcept {
    for (const char ch : sv) {
        const auto uch = static_cast<unsigned char>(ch);
        if (uch <= 0x20U || uch == 0x7FU) {
            return true;
        }
    }
    return false;
}

bool contains_ascii_control(std::string_view sv) noexcept {
    for (const char ch : sv) {
        const auto uch = static_cast<unsigned char>(ch);
        if (uch < 0x20U || uch == 0x7FU) {
            return true;
        }
    }
    return false;
}

} // namespace

bool is_valid_sha256_hex(std::string_view value) noexcept {
    if (value.size() != kSha256HexLength) {
        return false;
    }
    for (const char ch : value) {
        const bool is_hex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
        if (!is_hex) {
            return false;
        }
    }
    return true;
}

std::string normalize_hex_lower(std::string_view value) {
    return to_lower_ascii(value);
}

std::string_view to_string(ProxyType type) noexcept {
    switch (type) {
    case ProxyType::None:
        return "none";
    case ProxyType::Http:
        return "http";
    case ProxyType::Socks5:
        return "socks5";
    }
    return "none";
}

std::optional<ProxyType> proxy_type_from_string(std::string_view value) noexcept {
    const std::string lower = to_lower_ascii(value);
    if (lower == "none") {
        return ProxyType::None;
    }
    if (lower == "http") {
        return ProxyType::Http;
    }
    if (lower == "socks5") {
        return ProxyType::Socks5;
    }
    return std::nullopt;
}

std::string_view to_string(DisappearingTimerPreset preset) noexcept {
    switch (preset) {
    case DisappearingTimerPreset::Off:
        return "off";
    case DisappearingTimerPreset::OneHour:
        return "1h";
    case DisappearingTimerPreset::TwentyFourHours:
        return "24h";
    case DisappearingTimerPreset::SevenDays:
        return "7d";
    }
    return "off";
}

std::optional<DisappearingTimerPreset> disappearing_timer_preset_from_string(std::string_view value) noexcept {
    const std::string lower = to_lower_ascii(value);
    if (lower == "off" || lower == "0") {
        return DisappearingTimerPreset::Off;
    }
    if (lower == "1h" || lower == "3600") {
        return DisappearingTimerPreset::OneHour;
    }
    if (lower == "24h" || lower == "86400") {
        return DisappearingTimerPreset::TwentyFourHours;
    }
    if (lower == "7d" || lower == "604800") {
        return DisappearingTimerPreset::SevenDays;
    }
    return std::nullopt;
}

std::optional<DisappearingTimerPreset> disappearing_timer_preset_from_seconds(int64_t seconds) noexcept {
    switch (seconds) {
    case 0:
        return DisappearingTimerPreset::Off;
    case 3600:
        return DisappearingTimerPreset::OneHour;
    case 86400:
        return DisappearingTimerPreset::TwentyFourHours;
    case 604800:
        return DisappearingTimerPreset::SevenDays;
    default:
        return std::nullopt;
    }
}

std::vector<std::string> ProxyConfig::validate() const {
    std::vector<std::string> errors;
    if (type != ProxyType::None && type != ProxyType::Http && type != ProxyType::Socks5) {
        errors.emplace_back("proxy.type is invalid");
        return errors;
    }

    if (type == ProxyType::None) {
        return errors;
    }

    if (host.empty()) {
        errors.emplace_back("proxy.host cannot be empty when proxy is enabled");
    } else if (host.size() > kMaxHostOrUserBytes || contains_ascii_control_or_whitespace(host)) {
        errors.emplace_back("proxy.host contains invalid characters or exceeds 255 bytes");
    }

    if (port == 0U) {
        errors.emplace_back("proxy.port must be between 1 and 65535 when proxy is enabled");
    }

    if (username.size() > kMaxHostOrUserBytes || contains_ascii_control(username)) {
        errors.emplace_back("proxy.username contains invalid control characters or exceeds 255 bytes");
    }

    return errors;
}

bool ProxyConfig::is_valid() const noexcept {
    return validate().empty();
}

std::string TlsPinConfig::normalized_pin() const {
    return normalize_hex_lower(pinned_spki_sha256_hex);
}

std::vector<std::string> TlsPinConfig::validate() const {
    std::vector<std::string> errors;

    if (custom_gateway_port == 0U) {
        errors.emplace_back("tls.custom_gateway_port must be between 1 and 65535");
    }

    if (!custom_gateway_host.empty() && (custom_gateway_host.size() > kMaxHostOrUserBytes ||
                                         contains_ascii_control_or_whitespace(custom_gateway_host))) {
        errors.emplace_back("tls.custom_gateway_host contains invalid characters or exceeds 255 bytes");
    }

    if (!pinned_spki_sha256_hex.empty() && !is_valid_sha256_hex(pinned_spki_sha256_hex)) {
        errors.emplace_back("tls.pinned_spki_sha256_hex must be empty or a valid 64-character hex SHA-256 digest");
    }

    return errors;
}

bool TlsPinConfig::is_valid() const noexcept {
    return validate().empty();
}

std::vector<std::string> UserSettings::validate() const {
    std::vector<std::string> errors;

    if (theme_mode < kMinThemeMode || theme_mode > kMaxThemeMode) {
        errors.emplace_back("theme_mode must be 0 (System), 1 (Dark), or 2 (Light)");
    }

    if (!std::isfinite(font_scale) || font_scale < kMinFontScale || font_scale > kMaxFontScale) {
        errors.emplace_back("font_scale must be finite and within [0.85, 1.40]");
    }

    if (!disappearing_timer_preset_from_seconds(static_cast<int64_t>(default_disappearing_timer)).has_value()) {
        errors.emplace_back("default_disappearing_timer must be Off, OneHour, TwentyFourHours, or SevenDays");
    }

    if (schema_version == 0U) {
        errors.emplace_back("schema_version must be >= 1");
    }

    if (updated_at_ms < 0) {
        errors.emplace_back("updated_at_ms must be non-negative");
    }

    for (auto& err : proxy.validate()) {
        errors.push_back(std::move(err));
    }
    for (auto& err : tls.validate()) {
        errors.push_back(std::move(err));
    }

    return errors;
}

bool UserSettings::is_valid() const noexcept {
    return validate().empty();
}

std::string UserSettings::to_json() const {
    nlohmann::json proxy_json = nlohmann::json::object();
    proxy_json["type"] = std::string(to_string(proxy.type));
    proxy_json["host"] = proxy.host;
    proxy_json["port"] = proxy.port;
    proxy_json["username"] = proxy.username;

    nlohmann::json tls_json = nlohmann::json::object();
    tls_json["custom_gateway_host"] = tls.custom_gateway_host;
    tls_json["custom_gateway_port"] = tls.custom_gateway_port;
    tls_json["pinned_spki_sha256_hex"] = tls.normalized_pin();
    tls_json["enforce_strict_pinning"] = tls.enforce_strict_pinning;

    nlohmann::json root = nlohmann::json::object();
    root["schema_version"] = schema_version;
    root["updated_at_ms"] = updated_at_ms;
    root["theme_mode"] = theme_mode;
    root["font_scale"] = font_scale;
    root["high_contrast_enabled"] = high_contrast_enabled;
    root["read_receipts_enabled"] = read_receipts_enabled;
    root["default_disappearing_timer_seconds"] = static_cast<int64_t>(default_disappearing_timer);
    root["mfa_required_on_login"] = mfa_required_on_login;
    root["hardware_key_enforced"] = hardware_key_enforced;
    root["recovery_phrase_verified"] = recovery_phrase_verified;
    root["use_live_gateway_transport"] = use_live_gateway_transport;
    root["proxy"] = std::move(proxy_json);
    root["tls"] = std::move(tls_json);
    return root.dump();
}

std::optional<UserSettings> UserSettings::from_json(std::string_view json_str) {
    const nlohmann::json j = nlohmann::json::parse(json_str.begin(), json_str.end(), nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        return std::nullopt;
    }

    UserSettings out;

    if (const auto it = j.find("schema_version"); it != j.end()) {
        if (!it->is_number_integer()) {
            return std::nullopt;
        }
        const int64_t raw_ver = it->get<int64_t>();
        if (raw_ver < 1 || raw_ver > static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
            return std::nullopt;
        }
        out.schema_version = static_cast<uint32_t>(raw_ver);
    }

    if (const auto it = j.find("updated_at_ms"); it != j.end()) {
        if (!it->is_number_integer()) {
            return std::nullopt;
        }
        out.updated_at_ms = it->get<int64_t>();
    }

    if (const auto it = j.find("theme_mode"); it != j.end()) {
        if (!it->is_number_integer()) {
            return std::nullopt;
        }
        out.theme_mode = it->get<int>();
    }

    if (const auto it = j.find("font_scale"); it != j.end()) {
        if (!it->is_number()) {
            return std::nullopt;
        }
        out.font_scale = it->get<double>();
    }

    if (const auto it = j.find("high_contrast_enabled"); it != j.end()) {
        if (!it->is_boolean()) {
            return std::nullopt;
        }
        out.high_contrast_enabled = it->get<bool>();
    }

    if (const auto it = j.find("read_receipts_enabled"); it != j.end()) {
        if (!it->is_boolean()) {
            return std::nullopt;
        }
        out.read_receipts_enabled = it->get<bool>();
    }

    if (const auto it = j.find("default_disappearing_timer_seconds"); it != j.end()) {
        if (!it->is_number_integer()) {
            return std::nullopt;
        }
        const auto parsed_timer = disappearing_timer_preset_from_seconds(it->get<int64_t>());
        if (!parsed_timer.has_value()) {
            return std::nullopt;
        }
        out.default_disappearing_timer = *parsed_timer;
    }

    if (const auto it = j.find("mfa_required_on_login"); it != j.end()) {
        if (!it->is_boolean()) {
            return std::nullopt;
        }
        out.mfa_required_on_login = it->get<bool>();
    }

    if (const auto it = j.find("hardware_key_enforced"); it != j.end()) {
        if (!it->is_boolean()) {
            return std::nullopt;
        }
        out.hardware_key_enforced = it->get<bool>();
    }

    if (const auto it = j.find("recovery_phrase_verified"); it != j.end()) {
        if (!it->is_boolean()) {
            return std::nullopt;
        }
        out.recovery_phrase_verified = it->get<bool>();
    }

    if (const auto it = j.find("use_live_gateway_transport"); it != j.end()) {
        if (!it->is_boolean()) {
            return std::nullopt;
        }
        out.use_live_gateway_transport = it->get<bool>();
    }

    if (const auto proxy_it = j.find("proxy"); proxy_it != j.end()) {
        if (!proxy_it->is_object()) {
            return std::nullopt;
        }
        if (const auto type_it = proxy_it->find("type"); type_it != proxy_it->end()) {
            if (!type_it->is_string()) {
                return std::nullopt;
            }
            const auto parsed_type = proxy_type_from_string(type_it->get<std::string>());
            if (!parsed_type.has_value()) {
                return std::nullopt;
            }
            out.proxy.type = *parsed_type;
        }
        if (const auto host_it = proxy_it->find("host"); host_it != proxy_it->end()) {
            if (!host_it->is_string()) {
                return std::nullopt;
            }
            out.proxy.host = host_it->get<std::string>();
        }
        if (const auto port_it = proxy_it->find("port"); port_it != proxy_it->end()) {
            if (!port_it->is_number_integer()) {
                return std::nullopt;
            }
            const int64_t raw_port = port_it->get<int64_t>();
            if (raw_port < 0 || raw_port > 65535) {
                return std::nullopt;
            }
            out.proxy.port = static_cast<uint16_t>(raw_port);
        }
        if (const auto user_it = proxy_it->find("username"); user_it != proxy_it->end()) {
            if (!user_it->is_string()) {
                return std::nullopt;
            }
            out.proxy.username = user_it->get<std::string>();
        }
    }

    if (const auto tls_it = j.find("tls"); tls_it != j.end()) {
        if (!tls_it->is_object()) {
            return std::nullopt;
        }
        if (const auto host_it = tls_it->find("custom_gateway_host"); host_it != tls_it->end()) {
            if (!host_it->is_string()) {
                return std::nullopt;
            }
            out.tls.custom_gateway_host = host_it->get<std::string>();
        }
        if (const auto port_it = tls_it->find("custom_gateway_port"); port_it != tls_it->end()) {
            if (!port_it->is_number_integer()) {
                return std::nullopt;
            }
            const int64_t raw_port = port_it->get<int64_t>();
            if (raw_port < 0 || raw_port > 65535) {
                return std::nullopt;
            }
            out.tls.custom_gateway_port = static_cast<uint16_t>(raw_port);
        }
        if (const auto pin_it = tls_it->find("pinned_spki_sha256_hex"); pin_it != tls_it->end()) {
            if (!pin_it->is_string()) {
                return std::nullopt;
            }
            out.tls.pinned_spki_sha256_hex = normalize_hex_lower(pin_it->get<std::string>());
        }
        if (const auto enforce_it = tls_it->find("enforce_strict_pinning"); enforce_it != tls_it->end()) {
            if (!enforce_it->is_boolean()) {
                return std::nullopt;
            }
            out.tls.enforce_strict_pinning = enforce_it->get<bool>();
        }
    }

    if (!out.is_valid()) {
        return std::nullopt;
    }
    return out;
}

} // namespace securecloud::client::domain
