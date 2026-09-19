#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace securecloud::common::configuration {

/// Abstract source for retrieving configuration values (e.g. process environment, in-memory map).
class ConfigurationSource {
  public:
    virtual ~ConfigurationSource() = default;

    /// Retrieves the configuration value associated with the given key.
    /// Returns std::nullopt if the key is not set.
    [[nodiscard]] virtual std::optional<std::string> get(std::string_view key) const = 0;
};

/// Configuration source backed by the host process environment (std::getenv).
/// Guarantees null-termination safety when passing keys to C library functions.
class ProcessEnvironmentSource final : public ConfigurationSource {
  public:
    ProcessEnvironmentSource() = default;
    ~ProcessEnvironmentSource() override = default;

    [[nodiscard]] std::optional<std::string> get(std::string_view key) const override;
};

/// In-memory configuration source for deterministic, thread-safe unit and integration testing.
/// Isolates tests from host process environment mutations.
class InMemoryConfigurationSource final : public ConfigurationSource {
  public:
    InMemoryConfigurationSource() = default;
    explicit InMemoryConfigurationSource(std::unordered_map<std::string, std::string> values);
    ~InMemoryConfigurationSource() override = default;

    void set(std::string key, std::string value);
    void unset(std::string_view key);
    void clear() noexcept;

    [[nodiscard]] std::optional<std::string> get(std::string_view key) const override;

  private:
    std::unordered_map<std::string, std::string> m_values;
};

} // namespace securecloud::common::configuration
