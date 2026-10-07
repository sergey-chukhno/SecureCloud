#include "auth/crypto/token_crypto.hpp"

#include <array>
#include <iomanip>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace securecloud::auth::crypto {

// ============================================================================
// 1. Base64Url Implementation
// ============================================================================

namespace {

constexpr char kBase64UrlChars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int base64_char_value(char c) noexcept {
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '-')
        return 62;
    if (c == '_')
        return 63;
    return -1;
}

} // namespace

std::string Base64Url::encode(std::string_view input) {
    return encode(std::vector<uint8_t>(input.begin(), input.end()));
}

std::string Base64Url::encode(const std::vector<uint8_t>& input) {
    std::string encoded;
    encoded.reserve(((input.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i < input.size()) {
        const size_t remaining = input.size() - i;
        uint32_t octet_a = input[i++];
        uint32_t octet_b = (remaining > 1) ? input[i++] : 0;
        uint32_t octet_c = (remaining > 2) ? input[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        encoded.push_back(kBase64UrlChars[(triple >> 18) & 0x3F]);
        encoded.push_back(kBase64UrlChars[(triple >> 12) & 0x3F]);

        if (remaining > 1) {
            encoded.push_back(kBase64UrlChars[(triple >> 6) & 0x3F]);
        }
        if (remaining > 2) {
            encoded.push_back(kBase64UrlChars[triple & 0x3F]);
        }
    }

    return encoded;
}

std::optional<std::string> Base64Url::decode(std::string_view input) {
    auto bytes = decode_bytes(input);
    if (!bytes.has_value()) {
        return std::nullopt;
    }
    return std::string(bytes->begin(), bytes->end());
}

std::optional<std::vector<uint8_t>> Base64Url::decode_bytes(std::string_view input) {
    // Strip trailing padding characters if present
    while (!input.empty() && input.back() == '=') {
        input.remove_suffix(1);
    }

    if (input.empty()) {
        return std::vector<uint8_t>{};
    }

    if (input.size() % 4 == 1) {
        return std::nullopt; // Single residual base64 char is invalid
    }

    std::vector<uint8_t> decoded;
    decoded.reserve((input.size() * 3) / 4);

    size_t i = 0;
    while (i < input.size()) {
        const size_t chunk_len = std::min<size_t>(4, input.size() - i);
        std::array<int, 4> vals = {-1, -1, -1, -1};

        for (size_t j = 0; j < chunk_len; ++j) {
            vals[j] = base64_char_value(input[i + j]);
            if (vals[j] < 0) {
                return std::nullopt; // Invalid character
            }
        }
        i += chunk_len;

        if (chunk_len == 2) {
            auto val = (static_cast<uint32_t>(vals[0]) << 6) | static_cast<uint32_t>(vals[1]);
            decoded.push_back(static_cast<uint8_t>((val >> 4) & 0xFF));
        } else if (chunk_len == 3) {
            auto val = (static_cast<uint32_t>(vals[0]) << 12) | (static_cast<uint32_t>(vals[1]) << 6) |
                       static_cast<uint32_t>(vals[2]);
            decoded.push_back(static_cast<uint8_t>((val >> 10) & 0xFF));
            decoded.push_back(static_cast<uint8_t>((val >> 2) & 0xFF));
        } else if (chunk_len == 4) {
            auto val = (static_cast<uint32_t>(vals[0]) << 18) | (static_cast<uint32_t>(vals[1]) << 12) |
                       (static_cast<uint32_t>(vals[2]) << 6) | static_cast<uint32_t>(vals[3]);
            decoded.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
            decoded.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
            decoded.push_back(static_cast<uint8_t>(val & 0xFF));
        }
    }

    return decoded;
}

bool Base64Url::constant_time_equals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

// ============================================================================
// 2. Ed25519TokenSigner Implementation
// ============================================================================

struct Ed25519TokenSigner::Impl {
    EVP_PKEY* pkey{nullptr};

    ~Impl() {
        if (pkey) {
            EVP_PKEY_free(pkey);
            pkey = nullptr;
        }
    }
};

Ed25519TokenSigner::Ed25519TokenSigner(std::string key_id)
    : impl_(std::make_unique<Impl>()), key_id_(std::move(key_id)) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx) {
        throw std::runtime_error("Failed to initialize Ed25519 key generation context");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize Ed25519 keygen");
    }

    if (EVP_PKEY_keygen(ctx, &impl_->pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to generate Ed25519 keypair");
    }

    EVP_PKEY_CTX_free(ctx);
}

std::unique_ptr<Ed25519TokenSigner> Ed25519TokenSigner::from_private_key_pem(std::string_view pem_content,
                                                                             std::string key_id) {
    auto signer = std::unique_ptr<Ed25519TokenSigner>(new Ed25519TokenSigner(std::move(key_id)));
    if (signer->impl_->pkey) {
        EVP_PKEY_free(signer->impl_->pkey);
        signer->impl_->pkey = nullptr;
    }

    BIO* bio = BIO_new_mem_buf(pem_content.data(), static_cast<int>(pem_content.size()));
    if (!bio) {
        throw std::runtime_error("Failed to allocate memory BIO for private key");
    }

    signer->impl_->pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!signer->impl_->pkey) {
        throw std::runtime_error("Failed to parse Ed25519 private key from PEM");
    }

    if (EVP_PKEY_get_base_id(signer->impl_->pkey) != EVP_PKEY_ED25519) {
        throw std::runtime_error("Private key in PEM is not an Ed25519 key");
    }

    return signer;
}

std::string Ed25519TokenSigner::export_private_key_pem() const {
    if (!impl_ || !impl_->pkey) {
        throw std::runtime_error("Invalid signer state: uninitialized private key");
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw std::runtime_error("Failed to allocate memory BIO");
    }

    if (PEM_write_bio_PKCS8PrivateKey(bio, impl_->pkey, nullptr, nullptr, 0, nullptr, nullptr) <= 0) {
        BIO_free(bio);
        throw std::runtime_error("Failed to write private key to PEM");
    }

    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    std::string result(mem->data, mem->length);
    BIO_free(bio);

    return result;
}

Ed25519TokenSigner::~Ed25519TokenSigner() = default;
Ed25519TokenSigner::Ed25519TokenSigner(Ed25519TokenSigner&& other) noexcept = default;
Ed25519TokenSigner& Ed25519TokenSigner::operator=(Ed25519TokenSigner&& other) noexcept = default;

std::string Ed25519TokenSigner::sign(std::string_view payload) const {
    if (!impl_ || !impl_->pkey) {
        throw std::runtime_error("Invalid signer state: uninitialized private key");
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to allocate OpenSSL message digest context");
    }

    // For Ed25519, digest algorithm MUST be NULL
    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, impl_->pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize Ed25519 digest sign");
    }

    size_t sig_len = 0;
    if (EVP_DigestSign(ctx, nullptr, &sig_len, reinterpret_cast<const unsigned char*>(payload.data()),
                       payload.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to determine Ed25519 signature length");
    }

    std::vector<uint8_t> signature(sig_len);
    if (EVP_DigestSign(ctx, signature.data(), &sig_len, reinterpret_cast<const unsigned char*>(payload.data()),
                       payload.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to compute Ed25519 signature");
    }
    signature.resize(sig_len);
    EVP_MD_CTX_free(ctx);

    return Base64Url::encode(signature);
}

std::string Ed25519TokenSigner::get_public_key_pem() const {
    if (!impl_ || !impl_->pkey) {
        throw std::runtime_error("Invalid signer state: uninitialized private key");
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw std::runtime_error("Failed to allocate memory BIO");
    }

    if (PEM_write_bio_PUBKEY(bio, impl_->pkey) <= 0) {
        BIO_free(bio);
        throw std::runtime_error("Failed to write public key to PEM");
    }

    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    std::string result(mem->data, mem->length);
    BIO_free(bio);

    return result;
}

std::vector<uint8_t> Ed25519TokenSigner::get_public_key_raw() const {
    if (!impl_ || !impl_->pkey) {
        throw std::runtime_error("Invalid signer state: uninitialized private key");
    }

    size_t len = 0;
    if (EVP_PKEY_get_raw_public_key(impl_->pkey, nullptr, &len) <= 0) {
        throw std::runtime_error("Failed to determine Ed25519 raw public key size");
    }

    std::vector<uint8_t> raw_bytes(len);
    if (EVP_PKEY_get_raw_public_key(impl_->pkey, raw_bytes.data(), &len) <= 0) {
        throw std::runtime_error("Failed to extract Ed25519 raw public key bytes");
    }
    raw_bytes.resize(len);

    return raw_bytes;
}

std::string Ed25519TokenSigner::get_key_id() const {
    return key_id_;
}

// ============================================================================
// 3. Ed25519TokenVerifier Implementation
// ============================================================================

struct Ed25519TokenVerifier::Impl {
    EVP_PKEY* pkey{nullptr};

    ~Impl() {
        if (pkey) {
            EVP_PKEY_free(pkey);
            pkey = nullptr;
        }
    }
};

std::unique_ptr<Ed25519TokenVerifier> Ed25519TokenVerifier::from_public_key_pem(std::string_view pem_content,
                                                                                std::string key_id) {
    auto verifier = std::unique_ptr<Ed25519TokenVerifier>(new Ed25519TokenVerifier());
    verifier->key_id_ = std::move(key_id);

    BIO* bio = BIO_new_mem_buf(pem_content.data(), static_cast<int>(pem_content.size()));
    if (!bio) {
        throw std::runtime_error("Failed to allocate memory BIO for public key");
    }

    verifier->impl_->pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!verifier->impl_->pkey) {
        throw std::runtime_error("Failed to parse Ed25519 public key from PEM");
    }

    if (EVP_PKEY_get_base_id(verifier->impl_->pkey) != EVP_PKEY_ED25519) {
        throw std::runtime_error("Public key in PEM is not an Ed25519 key");
    }

    return verifier;
}

std::unique_ptr<Ed25519TokenVerifier> Ed25519TokenVerifier::from_public_key_raw(const std::vector<uint8_t>& raw_bytes,
                                                                                std::string key_id) {
    auto verifier = std::unique_ptr<Ed25519TokenVerifier>(new Ed25519TokenVerifier());
    verifier->key_id_ = std::move(key_id);

    verifier->impl_->pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, raw_bytes.data(), raw_bytes.size());

    if (!verifier->impl_->pkey) {
        throw std::runtime_error("Failed to create Ed25519 public key from raw bytes");
    }

    return verifier;
}

std::unique_ptr<Ed25519TokenVerifier> Ed25519TokenVerifier::from_signer(const ITokenSigner& signer) {
    return from_public_key_raw(signer.get_public_key_raw(), signer.get_key_id());
}

Ed25519TokenVerifier::~Ed25519TokenVerifier() = default;
Ed25519TokenVerifier::Ed25519TokenVerifier(Ed25519TokenVerifier&& other) noexcept = default;
Ed25519TokenVerifier& Ed25519TokenVerifier::operator=(Ed25519TokenVerifier&& other) noexcept = default;

Ed25519TokenVerifier::Ed25519TokenVerifier() : impl_(std::make_unique<Impl>()) {}

bool Ed25519TokenVerifier::verify(std::string_view payload, std::string_view signature_base64url) const {
    auto signature_bytes = Base64Url::decode_bytes(signature_base64url);
    if (!signature_bytes.has_value()) {
        return false;
    }
    return verify_raw(payload, *signature_bytes);
}

bool Ed25519TokenVerifier::verify_raw(std::string_view payload, const std::vector<uint8_t>& signature_bytes) const {
    if (!impl_ || !impl_->pkey) {
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return false;
    }

    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, impl_->pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    int ret = EVP_DigestVerify(ctx, signature_bytes.data(), signature_bytes.size(),
                               reinterpret_cast<const unsigned char*>(payload.data()), payload.size());
    EVP_MD_CTX_free(ctx);

    return ret == 1;
}

std::string Ed25519TokenVerifier::get_key_id() const {
    return key_id_;
}

// ============================================================================
// 4. SecureRandomTokenGenerator Implementation
// ============================================================================

std::vector<uint8_t> SecureRandomTokenGenerator::generate_secure_bytes(size_t byte_count) {
    if (byte_count == 0) {
        return {};
    }

    std::vector<uint8_t> buffer(byte_count);
    if (RAND_bytes(buffer.data(), static_cast<int>(byte_count)) != 1) {
        throw std::runtime_error("OpenSSL RAND_bytes failed to produce cryptographically secure random bytes");
    }

    return buffer;
}

std::string SecureRandomTokenGenerator::generate_refresh_token(size_t entropy_bytes) {
    auto bytes = generate_secure_bytes(entropy_bytes);
    return "sc_rt_" + Base64Url::encode(bytes);
}

// ============================================================================
// 5. TokenHasher Implementation
// ============================================================================

std::string TokenHasher::compute_sha256_hex(std::string_view secret) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(secret.data()), secret.size(), hash);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char byte : hash) {
        oss << std::setw(2) << static_cast<int>(byte);
    }

    return oss.str();
}

bool TokenHasher::verify_hash(std::string_view secret, std::string_view expected_hash_hex) noexcept {
    const std::string computed = compute_sha256_hex(secret);
    return Base64Url::constant_time_equals(computed, expected_hash_hex);
}

} // namespace securecloud::auth::crypto
