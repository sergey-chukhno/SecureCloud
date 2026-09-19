#include "securecloud/configuration/secret_string.hpp"

#include <iostream>
#include <openssl/crypto.h>
#include <utility>

namespace securecloud::common::configuration {

SecretString::SecretString() noexcept = default;

SecretString::SecretString(std::string secret) noexcept : m_secret(std::move(secret)) {}

SecretString::SecretString(std::string_view secret) : m_secret(secret) {}

SecretString::SecretString(const char* secret) : m_secret(secret != nullptr ? secret : "") {}

SecretString::~SecretString() {
    wipe_buffer();
}

SecretString::SecretString(const SecretString& other) = default;

SecretString& SecretString::operator=(const SecretString& other) {
    if (this != &other) {
        wipe_buffer();
        m_secret = other.m_secret;
    }
    return *this;
}

SecretString::SecretString(SecretString&& other) noexcept : m_secret(std::move(other.m_secret)) {
    other.wipe_buffer();
    other.m_secret.clear();
}

SecretString& SecretString::operator=(SecretString&& other) noexcept {
    if (this != &other) {
        wipe_buffer();
        m_secret = std::move(other.m_secret);
        other.wipe_buffer();
        other.m_secret.clear();
    }
    return *this;
}

bool SecretString::empty() const noexcept {
    return m_secret.empty();
}

std::size_t SecretString::size() const noexcept {
    return m_secret.size();
}

const std::string& SecretString::expose_unredacted_secret() const noexcept {
    return m_secret;
}

void SecretString::wipe_buffer() noexcept {
    if (!m_secret.empty()) {
        OPENSSL_cleanse(m_secret.data(), m_secret.size());
    }
}

std::ostream& operator<<(std::ostream& os, const SecretString& /*secret*/) {
    os << "[REDACTED]";
    return os;
}

bool SecretString::operator==(const SecretString& other) const noexcept {
    return m_secret == other.m_secret;
}

bool SecretString::operator!=(const SecretString& other) const noexcept {
    return m_secret != other.m_secret;
}

} // namespace securecloud::common::configuration
