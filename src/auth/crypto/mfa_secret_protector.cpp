#include "auth/crypto/mfa_secret_protector.hpp"

#include <cstring>
#include <memory>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>

namespace securecloud::auth::crypto {

namespace {

int hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

std::array<uint8_t, 32> parse_key(std::string_view key_str) {
    std::array<uint8_t, 32> key{};
    if (key_str.size() == 32) {
        std::memcpy(key.data(), key_str.data(), 32);
        return key;
    }
    if (key_str.size() == 64) {
        for (size_t i = 0; i < 32; ++i) {
            const int hi = hex_nibble(key_str[i * 2]);
            const int lo = hex_nibble(key_str[i * 2 + 1]);
            if (hi < 0 || lo < 0) {
                throw std::invalid_argument("MfaSecretProtector: key contains invalid hex characters");
            }
            key[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
        return key;
    }
    throw std::invalid_argument("MfaSecretProtector: key must be either 32 raw bytes or 64 hexadecimal characters");
}

struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const noexcept {
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
};

using ScopedCipherCtx = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

} // namespace

MfaSecretProtector::MfaSecretProtector(std::span<const uint8_t, kKeySize> kek) {
    std::memcpy(kek_.data(), kek.data(), kKeySize);
}

MfaSecretProtector::MfaSecretProtector(std::string_view hex_or_raw_key) : kek_(parse_key(hex_or_raw_key)) {}

MfaSecretProtector::~MfaSecretProtector() {
    OPENSSL_cleanse(kek_.data(), kek_.size());
}

MfaSecretProtector::MfaSecretProtector(MfaSecretProtector&& other) noexcept {
    std::memcpy(kek_.data(), other.kek_.data(), kKeySize);
    OPENSSL_cleanse(other.kek_.data(), kKeySize);
}

MfaSecretProtector& MfaSecretProtector::operator=(MfaSecretProtector&& other) noexcept {
    if (this != &other) {
        OPENSSL_cleanse(kek_.data(), kKeySize);
        std::memcpy(kek_.data(), other.kek_.data(), kKeySize);
        OPENSSL_cleanse(other.kek_.data(), kKeySize);
    }
    return *this;
}

std::vector<uint8_t> MfaSecretProtector::encrypt(std::span<const uint8_t> plaintext, std::string_view aad) const {
    // 1. Generate 12-byte random IV
    std::array<uint8_t, kIvSize> iv{};
    if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
        throw std::runtime_error("MfaSecretProtector: RAND_bytes failed to generate IV");
    }

    ScopedCipherCtx ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw std::runtime_error("MfaSecretProtector: failed to allocate EVP_CIPHER_CTX");
    }

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw std::runtime_error("MfaSecretProtector: failed to initialize AES-256-GCM cipher");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kIvSize), nullptr) != 1) {
        throw std::runtime_error("MfaSecretProtector: failed to set IV length");
    }

    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, kek_.data(), iv.data()) != 1) {
        throw std::runtime_error("MfaSecretProtector: failed to set key and IV");
    }

    int out_len = 0;
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &out_len, reinterpret_cast<const uint8_t*>(aad.data()),
                              static_cast<int>(aad.size())) != 1) {
            throw std::runtime_error("MfaSecretProtector: failed to process AAD");
        }
    }

    std::vector<uint8_t> ciphertext(plaintext.size());
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &out_len, plaintext.data(),
                              static_cast<int>(plaintext.size())) != 1) {
            throw std::runtime_error("MfaSecretProtector: failed to encrypt plaintext");
        }
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + out_len, &final_len) != 1) {
        throw std::runtime_error("MfaSecretProtector: failed to finalize encryption");
    }

    std::array<uint8_t, kTagSize> tag{};
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(kTagSize), tag.data()) != 1) {
        throw std::runtime_error("MfaSecretProtector: failed to retrieve GCM authentication tag");
    }

    // Assemble wire layout: [IV (12)] || [Ciphertext (N)] || [Tag (16)]
    std::vector<uint8_t> result;
    result.reserve(kIvSize + ciphertext.size() + kTagSize);
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag.begin(), tag.end());

    return result;
}

std::vector<uint8_t> MfaSecretProtector::decrypt(std::span<const uint8_t> encrypted_payload,
                                                 std::string_view aad) const {
    if (encrypted_payload.size() < kMinCipherSize) {
        throw std::invalid_argument("MfaSecretProtector: encrypted payload is too short (min 28 bytes)");
    }

    const uint8_t* iv_ptr = encrypted_payload.data();
    const size_t ciphertext_size = encrypted_payload.size() - kIvSize - kTagSize;
    const uint8_t* ciphertext_ptr = encrypted_payload.data() + kIvSize;
    const uint8_t* tag_ptr = encrypted_payload.data() + kIvSize + ciphertext_size;

    ScopedCipherCtx ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw std::runtime_error("MfaSecretProtector: failed to allocate EVP_CIPHER_CTX");
    }

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw std::runtime_error("MfaSecretProtector: failed to initialize AES-256-GCM cipher");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kIvSize), nullptr) != 1) {
        throw std::runtime_error("MfaSecretProtector: failed to set IV length");
    }

    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, kek_.data(), iv_ptr) != 1) {
        throw std::runtime_error("MfaSecretProtector: failed to set key and IV");
    }

    int out_len = 0;
    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &out_len, reinterpret_cast<const uint8_t*>(aad.data()),
                              static_cast<int>(aad.size())) != 1) {
            throw std::runtime_error("MfaSecretProtector: failed to process AAD");
        }
    }

    std::vector<uint8_t> plaintext(ciphertext_size);
    if (ciphertext_size > 0) {
        if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &out_len, ciphertext_ptr,
                              static_cast<int>(ciphertext_size)) != 1) {
            throw std::runtime_error("MfaSecretProtector: failed to decrypt ciphertext");
        }
    }

    // Set expected GCM tag for authentication
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(kTagSize),
                            const_cast<uint8_t*>(tag_ptr)) != 1) {
        throw std::runtime_error("MfaSecretProtector: failed to set expected GCM tag");
    }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + out_len, &final_len) != 1) {
        // Tag verification failed or payload tampered
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw std::runtime_error(
            "MfaSecretProtector: authentication tag mismatch - payload tampered or incorrect key/AAD");
    }

    return plaintext;
}

} // namespace securecloud::auth::crypto
