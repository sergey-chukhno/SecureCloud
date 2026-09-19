#include "securecloud/configuration/config_parser.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>

namespace securecloud::common::configuration {

std::optional<uint16_t> ConfigParser::parse_uint16(std::string_view key, std::string_view value,
                                                   ValidationResult& errors, uint16_t min, uint16_t max) {
    if (value.empty()) {
        errors.add_error(std::string(key), "value cannot be empty");
        return std::nullopt;
    }

    uint32_t parsed_val = 0;
    const char* start = value.data();
    const char* end = value.data() + value.size();
    auto [ptr, ec] = std::from_chars(start, end, parsed_val);

    if (ec != std::errc() || ptr != end) {
        errors.add_error(std::string(key), "invalid integer value '" + std::string(value) + "'");
        return std::nullopt;
    }

    if (parsed_val < min || parsed_val > max) {
        errors.add_error(std::string(key), "value " + std::to_string(parsed_val) + " out of valid range [" +
                                               std::to_string(min) + ".." + std::to_string(max) + "]");
        return std::nullopt;
    }

    return static_cast<uint16_t>(parsed_val);
}

std::optional<bool> ConfigParser::parse_bool(std::string_view key, std::string_view value, ValidationResult& errors) {
    if (value.empty()) {
        errors.add_error(std::string(key), "value cannot be empty");
        return std::nullopt;
    }

    std::string lower(value);
    std::ranges::transform(lower, lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (lower == "true" || lower == "1") {
        return true;
    }
    if (lower == "false" || lower == "0") {
        return false;
    }

    errors.add_error(std::string(key),
                     "invalid boolean value '" + std::string(value) + "' (expected 'true', 'false', '1', or '0')");
    return std::nullopt;
}

std::optional<std::chrono::milliseconds> ConfigParser::parse_duration_ms(std::string_view key, std::string_view value,
                                                                         ValidationResult& errors, uint64_t min_ms,
                                                                         uint64_t max_ms) {
    if (value.empty()) {
        errors.add_error(std::string(key), "value cannot be empty");
        return std::nullopt;
    }

    uint64_t parsed_ms = 0;
    const char* start = value.data();
    const char* end = value.data() + value.size();
    auto [ptr, ec] = std::from_chars(start, end, parsed_ms);

    if (ec != std::errc() || ptr != end) {
        errors.add_error(std::string(key), "invalid duration integer '" + std::string(value) + "'");
        return std::nullopt;
    }

    if (parsed_ms < min_ms || parsed_ms > max_ms) {
        errors.add_error(std::string(key), "duration " + std::to_string(parsed_ms) + " ms out of valid range [" +
                                               std::to_string(min_ms) + ".." + std::to_string(max_ms) + " ms]");
        return std::nullopt;
    }

    return std::chrono::milliseconds(parsed_ms);
}

std::optional<std::filesystem::path> ConfigParser::parse_path(std::string_view key, std::string_view value,
                                                              ValidationResult& errors, bool must_exist) {
    if (value.empty()) {
        errors.add_error(std::string(key), "path cannot be empty");
        return std::nullopt;
    }

    std::filesystem::path path_obj(value);
    if (must_exist && !std::filesystem::exists(path_obj)) {
        errors.add_error(std::string(key), "path does not exist on disk: '" + path_obj.string() + "'");
        return std::nullopt;
    }

    return path_obj.lexically_normal();
}

std::optional<std::string> ConfigParser::parse_string(std::string_view key, std::string_view value,
                                                      ValidationResult& errors, bool allow_empty) {
    if (!allow_empty && value.empty()) {
        errors.add_error(std::string(key), "string value cannot be empty");
        return std::nullopt;
    }

    return std::string(value);
}

} // namespace securecloud::common::configuration
