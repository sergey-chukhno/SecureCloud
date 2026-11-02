#pragma once

#include "securecloud/configuration/validation_error.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

namespace securecloud::common::configuration {

/// Strongly-typed parsing utilities for configuration values with boundary validation.
class ConfigParser final {
  public:
    /// Parses an integer string as a uint16_t, validating min <= value <= max (default 1..65535).
    static std::optional<uint16_t> parse_uint16(std::string_view key, std::string_view value, ValidationResult& errors,
                                                uint16_t min = 1, uint16_t max = 65535);

    /// Parses an integer string as a uint32_t, validating min <= value <= max (default 0..UINT32_MAX).
    static std::optional<uint32_t> parse_uint32(std::string_view key, std::string_view value, ValidationResult& errors,
                                                uint32_t min = 0, uint32_t max = std::numeric_limits<uint32_t>::max());

    /// Parses an integer string as a uint64_t, validating min <= value <= max (default 0..UINT64_MAX).
    static std::optional<uint64_t> parse_uint64(std::string_view key, std::string_view value, ValidationResult& errors,
                                                uint64_t min = 0, uint64_t max = std::numeric_limits<uint64_t>::max());

    /// Parses a boolean string (accepts true/false/1/0, case-insensitive).
    static std::optional<bool> parse_bool(std::string_view key, std::string_view value, ValidationResult& errors);

    /// Parses an integer duration in milliseconds with minimum and maximum bounds.
    static std::optional<std::chrono::milliseconds> parse_duration_ms(std::string_view key, std::string_view value,
                                                                      ValidationResult& errors, uint64_t min_ms = 1,
                                                                      uint64_t max_ms = 86400000); // 1 day max

    /// Parses and normalizes a filesystem path. Optionally verifies that the path exists.
    static std::optional<std::filesystem::path> parse_path(std::string_view key, std::string_view value,
                                                           ValidationResult& errors, bool must_exist = false);

    /// Parses a string, optionally requiring it to be non-empty.
    static std::optional<std::string> parse_string(std::string_view key, std::string_view value,
                                                   ValidationResult& errors, bool allow_empty = false);
};

} // namespace securecloud::common::configuration
