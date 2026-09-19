#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace securecloud::common::configuration {

/// Represents an individual configuration validation failure.
/// Strictly excludes sensitive secret payloads from the recorded diagnostic.
class ValidationError final {
  public:
    ValidationError(std::string setting_key, std::string message);

    [[nodiscard]] const std::string& setting_key() const noexcept { return m_setting_key; }
    [[nodiscard]] const std::string& message() const noexcept { return m_message; }

    [[nodiscard]] std::string to_string() const;

  private:
    std::string m_setting_key;
    std::string m_message;
};

/// Accumulator for configuration validation diagnostics during startup.
class ValidationResult final {
  public:
    ValidationResult() = default;

    void add_error(std::string setting_key, std::string message);
    void add_error(ValidationError error);

    [[nodiscard]] bool is_valid() const noexcept { return m_errors.empty(); }
    [[nodiscard]] bool has_errors() const noexcept { return !m_errors.empty(); }

    [[nodiscard]] const std::vector<ValidationError>& errors() const noexcept { return m_errors; }

    /// Formats all accumulated errors into a multi-line diagnostic string.
    [[nodiscard]] std::string to_string() const;

  private:
    std::vector<ValidationError> m_errors;
};

} // namespace securecloud::common::configuration
