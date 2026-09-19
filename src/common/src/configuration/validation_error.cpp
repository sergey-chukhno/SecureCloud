#include "securecloud/configuration/validation_error.hpp"

#include <sstream>
#include <utility>

namespace securecloud::common::configuration {

ValidationError::ValidationError(std::string setting_key, std::string message)
    : m_setting_key(std::move(setting_key)), m_message(std::move(message)) {}

std::string ValidationError::to_string() const {
    return "'" + m_setting_key + "': " + m_message;
}

void ValidationResult::add_error(std::string setting_key, std::string message) {
    m_errors.emplace_back(std::move(setting_key), std::move(message));
}

void ValidationResult::add_error(ValidationError error) {
    m_errors.push_back(std::move(error));
}

std::string ValidationResult::to_string() const {
    if (m_errors.empty()) {
        return "";
    }
    std::ostringstream oss;
    for (std::size_t i = 0; i < m_errors.size(); ++i) {
        if (i > 0) {
            oss << "\n";
        }
        oss << "  - " << m_errors[i].to_string();
    }
    return oss.str();
}

} // namespace securecloud::common::configuration
