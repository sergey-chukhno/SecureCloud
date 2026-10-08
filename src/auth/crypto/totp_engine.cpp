#include "auth/crypto/totp_engine.hpp"

#include <cmath>
#include <iomanip>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sstream>
#include <stdexcept>

namespace securecloud::auth::crypto {

namespace {

std::string url_encode(std::string_view value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (const char c : value) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2) << std::uppercase << (static_cast<int>(c) & 0xFF);
        }
    }

    return escaped.str();
}

bool constant_time_equals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

uint32_t power_of_ten(uint32_t digits) {
    uint32_t val = 1;
    for (uint32_t i = 0; i < digits; ++i) {
        val *= 10;
    }
    return val;
}

} // namespace

TotpEngine::TotpEngine(TotpConfig config) : config_(config) {
    if (config_.digits == 0 || config_.digits > 10) {
        throw std::invalid_argument("TotpEngine: digits must be between 1 and 10");
    }
    if (config_.time_step_seconds == 0) {
        throw std::invalid_argument("TotpEngine: time_step_seconds cannot be zero");
    }
    if (config_.drift_window_steps < 0) {
        throw std::invalid_argument("TotpEngine: drift_window_steps cannot be negative");
    }
}

std::vector<uint8_t> TotpEngine::generate_secret_bytes(size_t num_bytes) {
    if (num_bytes == 0) {
        throw std::invalid_argument("TotpEngine: num_bytes must be greater than zero");
    }
    std::vector<uint8_t> secret(num_bytes);
    if (RAND_bytes(secret.data(), static_cast<int>(secret.size())) != 1) {
        throw std::runtime_error("TotpEngine: OpenSSL RAND_bytes failed to generate secret");
    }
    return secret;
}

std::string TotpEngine::compute_code(std::span<const uint8_t> secret, uint64_t timestamp_seconds) const {
    if (secret.empty()) {
        throw std::invalid_argument("TotpEngine: secret cannot be empty");
    }

    // 1. Calculate time-step counter T = timestamp / step
    uint64_t counter = timestamp_seconds / config_.time_step_seconds;

    // 2. Encode 64-bit integer into 8 big-endian bytes
    uint8_t counter_bytes[8];
    for (int i = 7; i >= 0; --i) {
        counter_bytes[i] = static_cast<uint8_t>(counter & 0xFF);
        counter >>= 8;
    }

    // 3. Compute HMAC digest
    const EVP_MD* md = (config_.algorithm == TotpHashAlgorithm::Sha256) ? EVP_sha256() : EVP_sha1();
    uint8_t hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    if (HMAC(md, secret.data(), static_cast<int>(secret.size()), counter_bytes, sizeof(counter_bytes), hash,
             &hash_len) == nullptr) {
        throw std::runtime_error("TotpEngine: HMAC computation failed");
    }

    // 4. Dynamic Truncation (RFC 4226 §5.4)
    const uint8_t offset = hash[hash_len - 1] & 0x0F;
    const uint32_t binary_code =
        (static_cast<uint32_t>(hash[offset] & 0x7F) << 24) | (static_cast<uint32_t>(hash[offset + 1] & 0xFF) << 16) |
        (static_cast<uint32_t>(hash[offset + 2] & 0xFF) << 8) | static_cast<uint32_t>(hash[offset + 3] & 0xFF);

    // 5. Modulo 10^digits and format with leading zeros
    const uint32_t modulo = power_of_ten(config_.digits);
    const uint32_t otp = binary_code % modulo;

    std::ostringstream oss;
    oss << std::setw(static_cast<int>(config_.digits)) << std::setfill('0') << otp;
    return oss.str();
}

TotpVerificationResult TotpEngine::verify_code(std::span<const uint8_t> secret, std::string_view code,
                                               uint64_t timestamp_seconds) const {
    // Sanitize user code (remove any accidental whitespace)
    std::string clean_code;
    clean_code.reserve(code.size());
    for (const char c : code) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            clean_code.push_back(c);
        }
    }

    if (clean_code.size() != config_.digits) {
        return {false, 0};
    }

    const int64_t current_step = static_cast<int64_t>(timestamp_seconds / config_.time_step_seconds);
    const int window = config_.drift_window_steps;

    // Check [T - window, T + window]
    for (int drift = -window; drift <= window; ++drift) {
        const int64_t step_to_test = current_step + drift;
        if (step_to_test < 0) {
            continue;
        }

        const uint64_t time_to_test = static_cast<uint64_t>(step_to_test) * config_.time_step_seconds;
        const std::string candidate = compute_code(secret, time_to_test);

        if (constant_time_equals(clean_code, candidate)) {
            return {true, static_cast<uint64_t>(step_to_test)};
        }
    }

    return {false, 0};
}

std::string TotpEngine::generate_otpauth_uri(std::string_view issuer, std::string_view account_name,
                                             std::string_view base32_secret) const {
    std::ostringstream uri;
    uri << "otpauth://totp/";

    const std::string enc_issuer = url_encode(issuer);
    const std::string enc_account = url_encode(account_name);

    if (!issuer.empty()) {
        uri << enc_issuer << ":" << enc_account;
    } else {
        uri << enc_account;
    }

    uri << "?secret=" << base32_secret;

    if (!issuer.empty()) {
        uri << "&issuer=" << enc_issuer;
    }

    const std::string algo_str = (config_.algorithm == TotpHashAlgorithm::Sha256) ? "SHA256" : "SHA1";
    uri << "&algorithm=" << algo_str;
    uri << "&digits=" << config_.digits;
    uri << "&period=" << config_.time_step_seconds;

    return uri.str();
}

} // namespace securecloud::auth::crypto
