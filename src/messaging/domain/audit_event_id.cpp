#include "domain/audit_event_id.hpp"

#include <array>
#include <cctype>
#include <iomanip>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>

namespace securecloud::messaging::domain {

namespace {

[[nodiscard]] std::string format_uuid_bytes(const MessageId::bytes_type& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            oss << '-';
        }
        oss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return oss.str();
}

} // namespace

std::string generate_message_audit_event_id(const MessageId& msg_id, MessagingAuditEventType type) {
    if (msg_id.is_nil()) {
        throw std::invalid_argument("Cannot derive deterministic audit event_id from nil MessageId");
    }

    const std::string_view type_str = to_string(type);

    std::array<uint8_t, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("OpenSSL EVP_MD_CTX_new failed in generate_message_audit_event_id");
    }

    const bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
                    EVP_DigestUpdate(ctx, msg_id.bytes().data(), msg_id.bytes().size()) == 1 &&
                    EVP_DigestUpdate(ctx, ":", 1) == 1 &&
                    EVP_DigestUpdate(ctx, type_str.data(), type_str.size()) == 1 &&
                    EVP_DigestFinal_ex(ctx, digest.data(), &digest_len) == 1;

    EVP_MD_CTX_free(ctx);

    if (!ok || digest_len < 10) {
        throw std::runtime_error("OpenSSL SHA-256 digest failed in generate_message_audit_event_id");
    }

    MessageId::bytes_type out_bytes{};
    // Preserve original 48-bit Unix millisecond timestamp from MessageId (bytes 0..5)
    for (std::size_t i = 0; i < 6; ++i) {
        out_bytes[i] = msg_id.bytes()[i];
    }

    // RFC 9562 UUIDv7 version (0b0111) + deterministic 12-bit rand_a
    out_bytes[6] = static_cast<uint8_t>(0x70 | (digest[0] & 0x0F));
    out_bytes[7] = digest[1];

    // RFC 9562 variant (0b10xx) + deterministic 62-bit rand_b
    out_bytes[8] = static_cast<uint8_t>(0x80 | (digest[2] & 0x3F));
    for (std::size_t i = 3; i < 10; ++i) {
        out_bytes[6 + i] = digest[i];
    }

    return format_uuid_bytes(out_bytes);
}

std::string generate_audit_event_id() {
    return MessageId::generate_v7().to_string();
}

bool is_valid_audit_uuid_v7(std::string_view value) noexcept {
    if (value.size() != 36) {
        return false;
    }
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') {
                return false;
            }
            continue;
        }
        const unsigned char ch = static_cast<unsigned char>(value[i]);
        if (std::isxdigit(ch) == 0) {
            return false;
        }
    }
    if (value[14] != '7') {
        return false;
    }
    const char variant = static_cast<char>(std::tolower(static_cast<unsigned char>(value[19])));
    return variant == '8' || variant == '9' || variant == 'a' || variant == 'b';
}

} // namespace securecloud::messaging::domain
