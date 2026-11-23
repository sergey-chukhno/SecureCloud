#include "domain/crypto/file_crypto_engine.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace securecloud::client::domain::crypto {
namespace {

constexpr std::array<char, 16> kHexDigits = {'0', '1', '2', '3', '4', '5', '6', '7',
                                             '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

std::string bytes_to_lowercase_hex(std::span<const uint8_t> bytes) {
    std::string hex;
    hex.reserve(bytes.size() * 2U);
    for (const uint8_t byte : bytes) {
        hex.push_back(kHexDigits[static_cast<std::size_t>((byte >> 4U) & 0x0FU)]);
        hex.push_back(kHexDigits[static_cast<std::size_t>(byte & 0x0FU)]);
    }
    return hex;
}

std::string to_lower_ascii(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    for (const char ch : sv) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return out;
}

std::optional<uint8_t> hex_nibble(char ch) noexcept {
    if (ch >= '0' && ch <= '9') {
        return static_cast<uint8_t>(ch - '0');
    }
    if (ch >= 'a' && ch <= 'f') {
        return static_cast<uint8_t>(10 + (ch - 'a'));
    }
    if (ch >= 'A' && ch <= 'F') {
        return static_cast<uint8_t>(10 + (ch - 'A'));
    }
    return std::nullopt;
}

void append_u32_be(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>((value >> 24U) & 0xFFU));
    out.push_back(static_cast<uint8_t>((value >> 16U) & 0xFFU));
    out.push_back(static_cast<uint8_t>((value >> 8U) & 0xFFU));
    out.push_back(static_cast<uint8_t>(value & 0xFFU));
}

void append_bytes(std::vector<uint8_t>& out, std::string_view sv) {
    for (const char ch : sv) {
        out.push_back(static_cast<uint8_t>(static_cast<unsigned char>(ch)));
    }
}

common::configuration::SecretString make_secret_and_cleanse(std::string& buffer) {
    common::configuration::SecretString secret(std::string_view(buffer.data(), buffer.size()));
    if (!buffer.empty()) {
        OPENSSL_cleanse(buffer.data(), buffer.size());
    }
    buffer.clear();
    return secret;
}

} // namespace

void EvpMdCtxDeleter::operator()(evp_md_ctx_st* ctx) const noexcept {
    EVP_MD_CTX_free(ctx);
}

StreamingSha256::StreamingSha256() : ctx_(EVP_MD_CTX_new()) {
    initialized_ = ctx_ != nullptr && EVP_DigestInit_ex(ctx_.get(), EVP_sha256(), nullptr) == 1;
}

StreamingSha256::~StreamingSha256() = default;
StreamingSha256::StreamingSha256(StreamingSha256&&) noexcept = default;
StreamingSha256& StreamingSha256::operator=(StreamingSha256&&) noexcept = default;

bool StreamingSha256::is_valid() const noexcept {
    return ctx_ != nullptr && initialized_;
}

application::ClientResult<void> StreamingSha256::update(std::span<const uint8_t> data) {
    if (!is_valid() || finalized_) {
        return application::ClientResult<void>::error(
            application::ClientError::crypto("StreamingSha256 is uninitialized or already finalized"));
    }
    if (data.empty()) {
        return application::ClientResult<void>::ok();
    }
    if (EVP_DigestUpdate(ctx_.get(), data.data(), data.size()) != 1) {
        initialized_ = false;
        return application::ClientResult<void>::error(
            application::ClientError::crypto("OpenSSL EVP_DigestUpdate failed for SHA-256"));
    }
    return application::ClientResult<void>::ok();
}

application::ClientResult<std::string> StreamingSha256::finalize_hex() {
    if (!is_valid() || finalized_) {
        return application::ClientResult<std::string>::error(
            application::ClientError::crypto("StreamingSha256 cannot be finalized in current state"));
    }
    std::array<uint8_t, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx_.get(), digest.data(), &digest_len) != 1 || digest_len != 32U) {
        initialized_ = false;
        return application::ClientResult<std::string>::error(
            application::ClientError::crypto("OpenSSL EVP_DigestFinal_ex failed for SHA-256"));
    }
    finalized_ = true;
    return application::ClientResult<std::string>::ok(
        bytes_to_lowercase_hex(std::span<const uint8_t>(digest.data(), digest_len)));
}

application::ClientResult<void> StreamingSha256::reset() {
    if (!ctx_) {
        ctx_.reset(EVP_MD_CTX_new());
    }
    finalized_ = false;
    initialized_ = ctx_ != nullptr && EVP_DigestInit_ex(ctx_.get(), EVP_sha256(), nullptr) == 1;
    if (!initialized_) {
        return application::ClientResult<void>::error(
            application::ClientError::crypto("Failed to reset StreamingSha256 context"));
    }
    return application::ClientResult<void>::ok();
}

application::ClientResult<std::string> StreamingSha256::digest_hex(std::span<const uint8_t> data) {
    StreamingSha256 hasher;
    if (const auto upd = hasher.update(data); upd.is_error()) {
        return application::ClientResult<std::string>::error(upd.error());
    }
    return hasher.finalize_hex();
}

application::ClientResult<FileCryptoEngine> FileCryptoEngine::create(uint32_t wire_chunk_size) {
    if (wire_chunk_size <= kChunkOverheadBytes || wire_chunk_size > kMaxWireChunkSize) {
        return application::ClientResult<FileCryptoEngine>::error(
            application::ClientError::validation("Wire chunk size must be strictly between 28 B and 8 MiB"));
    }
    return application::ClientResult<FileCryptoEngine>::ok(FileCryptoEngine(wire_chunk_size));
}

application::ClientResult<uint32_t>
FileCryptoEngine::calculate_chunk_count(uint64_t plaintext_size_bytes) const noexcept {
    if (plaintext_size_bytes == 0ULL) {
        return application::ClientResult<uint32_t>::error(
            application::ClientError::validation("Plaintext file size must be greater than 0 bytes"));
    }
    if (plaintext_size_bytes > kMaxEncryptedFileSizeBytes) {
        return application::ClientResult<uint32_t>::error(
            application::ClientError::validation("Plaintext file size exceeds maximum 5 GiB backend limit"));
    }

    const uint64_t max_plaintext = static_cast<uint64_t>(max_plaintext_chunk_size());
    const uint64_t chunks = ((plaintext_size_bytes - 1ULL) / max_plaintext) + 1ULL;
    if (chunks > static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())) {
        return application::ClientResult<uint32_t>::error(
            application::ClientError::validation("Chunk count exceeds 32-bit protocol index limit"));
    }

    const uint64_t overhead_per_chunk = static_cast<uint64_t>(kChunkOverheadBytes);
    if (chunks > (kMaxEncryptedFileSizeBytes - plaintext_size_bytes) / overhead_per_chunk) {
        return application::ClientResult<uint32_t>::error(
            application::ClientError::validation("Encrypted file size with framing exceeds maximum 5 GiB limit"));
    }

    return application::ClientResult<uint32_t>::ok(static_cast<uint32_t>(chunks));
}

application::ClientResult<uint64_t>
FileCryptoEngine::calculate_encrypted_size(uint64_t plaintext_size_bytes) const noexcept {
    const auto chunk_count_res = calculate_chunk_count(plaintext_size_bytes);
    if (chunk_count_res.is_error()) {
        return application::ClientResult<uint64_t>::error(chunk_count_res.error());
    }
    const uint64_t total_overhead = static_cast<uint64_t>(chunk_count_res.value()) * kChunkOverheadBytes;
    return application::ClientResult<uint64_t>::ok(plaintext_size_bytes + total_overhead);
}

application::ClientResult<common::configuration::SecretString> FileCryptoEngine::generate_file_key() {
    std::array<uint8_t, kKeyBytes> key_bytes{};
    if (RAND_bytes(key_bytes.data(), static_cast<int>(key_bytes.size())) != 1) {
        OPENSSL_cleanse(key_bytes.data(), key_bytes.size());
        return application::ClientResult<common::configuration::SecretString>::error(
            application::ClientError::crypto("OpenSSL RAND_bytes failed generating 256-bit file key"));
    }

    std::string raw(reinterpret_cast<const char*>(key_bytes.data()), key_bytes.size());
    OPENSSL_cleanse(key_bytes.data(), key_bytes.size());
    return application::ClientResult<common::configuration::SecretString>::ok(make_secret_and_cleanse(raw));
}

application::ClientResult<common::configuration::SecretString>
FileCryptoEngine::encode_key_hex(const common::configuration::SecretString& raw_key) {
    if (raw_key.size() != kKeyBytes) {
        return application::ClientResult<common::configuration::SecretString>::error(
            application::ClientError::validation("Raw file key must be exactly 32 bytes for hex encoding"));
    }
    const std::string& bytes_str = raw_key.expose_unredacted_secret();
    std::string hex = bytes_to_lowercase_hex(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(bytes_str.data()), bytes_str.size()));
    return application::ClientResult<common::configuration::SecretString>::ok(make_secret_and_cleanse(hex));
}

application::ClientResult<common::configuration::SecretString>
FileCryptoEngine::decode_key_hex(const common::configuration::SecretString& hex_key) {
    if (hex_key.size() != static_cast<std::size_t>(kKeyBytes) * 2U) {
        return application::ClientResult<common::configuration::SecretString>::error(
            application::ClientError::validation("Hex-encoded file key must be exactly 64 hex characters"));
    }
    const std::string& hex_str = hex_key.expose_unredacted_secret();
    std::string raw;
    raw.reserve(kKeyBytes);

    for (std::size_t i = 0; i < hex_str.size(); i += 2U) {
        const auto hi = hex_nibble(hex_str[i]);
        const auto lo = hex_nibble(hex_str[i + 1U]);
        if (!hi.has_value() || !lo.has_value()) {
            OPENSSL_cleanse(raw.data(), raw.size());
            return application::ClientResult<common::configuration::SecretString>::error(
                application::ClientError::validation("Hex-encoded file key contains non-hexadecimal character"));
        }
        raw.push_back(static_cast<char>(((*hi) << 4U) | (*lo)));
    }
    return application::ClientResult<common::configuration::SecretString>::ok(make_secret_and_cleanse(raw));
}

application::ClientResult<std::vector<uint8_t>>
FileCryptoEngine::derive_chunk_iv(application::interfaces::ICryptoProvider& crypto,
                                  const common::configuration::SecretString& file_key, std::string_view file_id,
                                  uint32_t chunk_index) {
    if (file_key.size() != kKeyBytes) {
        return application::ClientResult<std::vector<uint8_t>>::error(
            application::ClientError::validation("File key must be 32 bytes for HKDF IV derivation"));
    }
    if (file_id.empty()) {
        return application::ClientResult<std::vector<uint8_t>>::error(
            application::ClientError::validation("File ID cannot be empty for HKDF IV derivation"));
    }

    std::vector<uint8_t> info;
    info.reserve(kIvDomainSeparator.size() + 2U + file_id.size() + sizeof(uint32_t));
    append_bytes(info, kIvDomainSeparator);
    info.push_back(0x00U);
    append_bytes(info, file_id);
    info.push_back(0x00U);
    append_u32_be(info, chunk_index);

    const auto hkdf_res = crypto.hkdf_extract_and_expand({}, file_key, info, kIvBytes);
    if (hkdf_res.is_error()) {
        return application::ClientResult<std::vector<uint8_t>>::error(hkdf_res.error());
    }

    const std::string& iv_str = hkdf_res.value().expose_unredacted_secret();
    if (iv_str.size() != kIvBytes) {
        return application::ClientResult<std::vector<uint8_t>>::error(
            application::ClientError::crypto("HKDF derived unexpected IV length"));
    }

    std::vector<uint8_t> iv(kIvBytes);
    std::copy_n(reinterpret_cast<const uint8_t*>(iv_str.data()), kIvBytes, iv.begin());
    return application::ClientResult<std::vector<uint8_t>>::ok(std::move(iv));
}

std::vector<uint8_t> FileCryptoEngine::build_chunk_aad(std::string_view file_id, uint32_t chunk_index, bool is_final) {
    std::vector<uint8_t> aad;
    aad.reserve(kAadDomainSeparator.size() + 1U + sizeof(uint32_t) + file_id.size() + sizeof(uint32_t) + 1U);
    append_bytes(aad, kAadDomainSeparator);
    aad.push_back(0x00U);
    append_u32_be(aad, static_cast<uint32_t>(file_id.size()));
    append_bytes(aad, file_id);
    append_u32_be(aad, chunk_index);
    aad.push_back(static_cast<uint8_t>(is_final ? 1U : 0U));
    return aad;
}

application::ClientResult<EncryptedChunkFrame>
FileCryptoEngine::encrypt_chunk(application::interfaces::ICryptoProvider& crypto,
                                const common::configuration::SecretString& file_key, std::string_view file_id,
                                uint32_t chunk_index, bool is_final, std::span<const uint8_t> plaintext) const {
    if (file_id.empty()) {
        return application::ClientResult<EncryptedChunkFrame>::error(
            application::ClientError::validation("File ID cannot be empty when encrypting chunk"));
    }
    if (file_key.size() != kKeyBytes) {
        return application::ClientResult<EncryptedChunkFrame>::error(
            application::ClientError::validation("File key must be 32 bytes when encrypting chunk"));
    }
    if (plaintext.empty() || plaintext.size() > static_cast<std::size_t>(max_plaintext_chunk_size())) {
        return application::ClientResult<EncryptedChunkFrame>::error(
            application::ClientError::validation("Plaintext chunk size exceeds configured chunk bounds"));
    }
    if (!is_final && plaintext.size() != static_cast<std::size_t>(max_plaintext_chunk_size())) {
        return application::ClientResult<EncryptedChunkFrame>::error(
            application::ClientError::validation("Non-terminal chunk must fill full wire chunk capacity"));
    }

    const auto iv_res = derive_chunk_iv(crypto, file_key, file_id, chunk_index);
    if (iv_res.is_error()) {
        return application::ClientResult<EncryptedChunkFrame>::error(iv_res.error());
    }

    const std::vector<uint8_t> aad = build_chunk_aad(file_id, chunk_index, is_final);
    const auto aead_res = crypto.encrypt_aes_gcm(file_key, iv_res.value(), plaintext, aad);
    if (aead_res.is_error()) {
        return application::ClientResult<EncryptedChunkFrame>::error(aead_res.error());
    }

    const auto& aead = aead_res.value();
    if (aead.iv.size() != kIvBytes || aead.auth_tag.size() != kTagBytes || aead.ciphertext.size() != plaintext.size()) {
        return application::ClientResult<EncryptedChunkFrame>::error(
            application::ClientError::crypto("Unexpected AEAD output framing sizes during chunk encryption"));
    }

    EncryptedChunkFrame frame;
    frame.framed_bytes.reserve(aead.iv.size() + aead.ciphertext.size() + aead.auth_tag.size());
    frame.framed_bytes.insert(frame.framed_bytes.end(), aead.iv.begin(), aead.iv.end());
    frame.framed_bytes.insert(frame.framed_bytes.end(), aead.ciphertext.begin(), aead.ciphertext.end());
    frame.framed_bytes.insert(frame.framed_bytes.end(), aead.auth_tag.begin(), aead.auth_tag.end());

    const auto sha_res = StreamingSha256::digest_hex(frame.framed_bytes);
    if (sha_res.is_error()) {
        return application::ClientResult<EncryptedChunkFrame>::error(sha_res.error());
    }
    frame.ciphertext_sha256 = sha_res.value();

    return application::ClientResult<EncryptedChunkFrame>::ok(std::move(frame));
}

application::ClientResult<std::vector<uint8_t>>
FileCryptoEngine::decrypt_chunk(application::interfaces::ICryptoProvider& crypto,
                                const common::configuration::SecretString& file_key, std::string_view file_id,
                                uint32_t chunk_index, bool is_final, std::span<const uint8_t> framed_bytes,
                                std::string_view expected_chunk_sha256) const {
    if (file_id.empty()) {
        return application::ClientResult<std::vector<uint8_t>>::error(
            application::ClientError::validation("File ID cannot be empty when decrypting chunk"));
    }
    if (file_key.size() != kKeyBytes) {
        return application::ClientResult<std::vector<uint8_t>>::error(
            application::ClientError::validation("File key must be 32 bytes when decrypting chunk"));
    }
    if (framed_bytes.size() <= static_cast<std::size_t>(kChunkOverheadBytes) ||
        framed_bytes.size() > static_cast<std::size_t>(wire_chunk_size_)) {
        return application::ClientResult<std::vector<uint8_t>>::error(
            application::ClientError::validation("Framed encrypted chunk size is outside valid bounds"));
    }
    if (!is_final && framed_bytes.size() != static_cast<std::size_t>(wire_chunk_size_)) {
        return application::ClientResult<std::vector<uint8_t>>::error(
            application::ClientError::validation("Non-terminal encrypted chunk size does not match wire chunk size"));
    }

    if (!expected_chunk_sha256.empty()) {
        const auto actual_sha = StreamingSha256::digest_hex(framed_bytes);
        if (actual_sha.is_error()) {
            return application::ClientResult<std::vector<uint8_t>>::error(actual_sha.error());
        }
        if (actual_sha.value() != to_lower_ascii(expected_chunk_sha256)) {
            return application::ClientResult<std::vector<uint8_t>>::error(
                application::ClientError::crypto("Chunk ciphertext SHA-256 verification failed"));
        }
    }

    const std::span<const uint8_t> wire_iv = framed_bytes.subspan(0U, kIvBytes);
    const std::size_t ciphertext_len = framed_bytes.size() - static_cast<std::size_t>(kChunkOverheadBytes);
    const std::span<const uint8_t> ciphertext = framed_bytes.subspan(kIvBytes, ciphertext_len);
    const std::span<const uint8_t> auth_tag = framed_bytes.subspan(kIvBytes + ciphertext_len, kTagBytes);

    const auto expected_iv_res = derive_chunk_iv(crypto, file_key, file_id, chunk_index);
    if (expected_iv_res.is_error()) {
        return application::ClientResult<std::vector<uint8_t>>::error(expected_iv_res.error());
    }
    if (CRYPTO_memcmp(wire_iv.data(), expected_iv_res.value().data(), kIvBytes) != 0) {
        return application::ClientResult<std::vector<uint8_t>>::error(
            application::ClientError::crypto("Chunk wire IV mismatch against deterministic HKDF derivation"));
    }

    const std::vector<uint8_t> aad = build_chunk_aad(file_id, chunk_index, is_final);
    const auto pt_res = crypto.decrypt_aes_gcm(file_key, wire_iv, ciphertext, auth_tag, aad);
    if (pt_res.is_error()) {
        return application::ClientResult<std::vector<uint8_t>>::error(pt_res.error());
    }

    const std::string& pt_str = pt_res.value().expose_unredacted_secret();
    std::vector<uint8_t> plaintext(pt_str.size());
    std::copy_n(reinterpret_cast<const uint8_t*>(pt_str.data()), pt_str.size(), plaintext.begin());
    return application::ClientResult<std::vector<uint8_t>>::ok(std::move(plaintext));
}

} // namespace securecloud::client::domain::crypto
