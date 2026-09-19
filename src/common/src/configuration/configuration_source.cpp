#include "securecloud/configuration/configuration_source.hpp"

#include <cstdlib>
#include <utility>

namespace securecloud::common::configuration {

std::optional<std::string> ProcessEnvironmentSource::get(std::string_view key) const {
    // Guarantees null-termination safety when passing key to std::getenv.
    std::string key_str(key);
    const char* val = std::getenv(key_str.c_str()); // NOLINT(concurrency-mt-unsafe)
    if (val != nullptr) {
        return std::string(val);
    }
    return std::nullopt;
}

InMemoryConfigurationSource::InMemoryConfigurationSource(std::unordered_map<std::string, std::string> values)
    : m_values(std::move(values)) {}

void InMemoryConfigurationSource::set(std::string key, std::string value) {
    m_values[std::move(key)] = std::move(value);
}

void InMemoryConfigurationSource::unset(std::string_view key) {
    m_values.erase(std::string(key));
}

void InMemoryConfigurationSource::clear() noexcept {
    m_values.clear();
}

std::optional<std::string> InMemoryConfigurationSource::get(std::string_view key) const {
    auto it = m_values.find(std::string(key));
    if (it != m_values.end()) {
        return it->second;
    }
    return std::nullopt;
}

} // namespace securecloud::common::configuration
