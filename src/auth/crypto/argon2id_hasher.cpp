#include "crypto/argon2id_hasher.hpp"

#include <algorithm>
#include <charconv>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace securecloud::auth::crypto {

namespace {

constexpr std::string_view kBase64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode_unpadded(const std::uint8_t* data, std::size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    std::size_t i = 0;
    while (i + 3 <= len) {
        std::uint32_t triple = (static_cast<std::uint32_t>(data[i]) << 16) |
                               (static_cast<std::uint32_t>(data[i + 1]) << 8) | static_cast<std::uint32_t>(data[i + 2]);
        out.push_back(kBase64Alphabet[(triple >> 18) & 0x3F]);
        out.push_back(kBase64Alphabet[(triple >> 12) & 0x3F]);
        out.push_back(kBase64Alphabet[(triple >> 6) & 0x3F]);
        out.push_back(kBase64Alphabet[triple & 0x3F]);
        i += 3;
    }

    if (i < len) {
        std::size_t remaining = len - i;
        std::uint32_t triple = static_cast<std::uint32_t>(data[i]) << 16;
        if (remaining == 2) {
            triple |= static_cast<std::uint32_t>(data[i + 1]) << 8;
        }

        out.push_back(kBase64Alphabet[(triple >> 18) & 0x3F]);
        out.push_back(kBase64Alphabet[(triple >> 12) & 0x3F]);
        if (remaining == 2) {
            out.push_back(kBase64Alphabet[(triple >> 6) & 0x3F]);
        }
    }

    return out;
}

std::optional<std::vector<std::uint8_t>> base64_decode_unpadded(std::string_view in) {
    auto decode_char = [](char c) -> int {
        if (c >= 'A' && c <= 'Z')
            return c - 'A';
        if (c >= 'a' && c <= 'z')
            return c - 'a' + 26;
        if (c >= '0' && c <= '9')
            return c - '0' + 52;
        if (c == '+')
            return 62;
        if (c == '/')
            return 63;
        return -1;
    };

    // Remove any trailing padding '=' if present
    while (!in.empty() && in.back() == '=') {
        in.remove_suffix(1);
    }

    if (in.empty()) {
        return std::vector<std::uint8_t>{};
    }

    std::vector<std::uint8_t> out;
    out.reserve((in.size() * 3) / 4);

    std::size_t i = 0;
    while (i + 4 <= in.size()) {
        int b0 = decode_char(in[i]);
        int b1 = decode_char(in[i + 1]);
        int b2 = decode_char(in[i + 2]);
        int b3 = decode_char(in[i + 3]);
        if (b0 < 0 || b1 < 0 || b2 < 0 || b3 < 0) {
            return std::nullopt;
        }

        std::uint32_t triple = (static_cast<std::uint32_t>(b0) << 18) | (static_cast<std::uint32_t>(b1) << 12) |
                               (static_cast<std::uint32_t>(b2) << 6) | static_cast<std::uint32_t>(b3);

        out.push_back(static_cast<std::uint8_t>((triple >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((triple >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(triple & 0xFF));
        i += 4;
    }

    std::size_t rem = in.size() - i;
    if (rem == 1) {
        return std::nullopt; // Single base64 character cannot encode valid bits
    }
    if (rem == 2) {
        int b0 = decode_char(in[i]);
        int b1 = decode_char(in[i + 1]);
        if (b0 < 0 || b1 < 0)
            return std::nullopt;
        std::uint32_t val = (static_cast<std::uint32_t>(b0) << 18) | (static_cast<std::uint32_t>(b1) << 12);
        out.push_back(static_cast<std::uint8_t>((val >> 16) & 0xFF));
    } else if (rem == 3) {
        int b0 = decode_char(in[i]);
        int b1 = decode_char(in[i + 1]);
        int b2 = decode_char(in[i + 2]);
        if (b0 < 0 || b1 < 0 || b2 < 0)
            return std::nullopt;
        std::uint32_t val = (static_cast<std::uint32_t>(b0) << 18) | (static_cast<std::uint32_t>(b1) << 12) |
                            (static_cast<std::uint32_t>(b2) << 6);
        out.push_back(static_cast<std::uint8_t>((val >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
    }

    return out;
}

struct ParsedPhc {
    std::uint32_t version{19};
    std::uint32_t memory_cost_kib{0};
    std::uint32_t iterations{0};
    std::uint32_t parallelism{0};
    std::vector<std::uint8_t> salt;
    std::vector<std::uint8_t> hash;
};

std::optional<ParsedPhc> parse_phc_verifier(std::string_view verifier) {
    // Format: $argon2id$v=19$m=65536,t=3,p=1$<salt_b64>$<hash_b64>
    if (!verifier.starts_with("$argon2id$")) {
        return std::nullopt;
    }

    std::vector<std::string_view> tokens;
    std::size_t start = 1; // skip leading '$'
    while (start < verifier.size()) {
        std::size_t end = verifier.find('$', start);
        if (end == std::string_view::npos) {
            tokens.push_back(verifier.substr(start));
            break;
        }
        tokens.push_back(verifier.substr(start, end - start));
        start = end + 1;
    }

    // Expected tokens: ["argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<hash>"]
    if (tokens.size() != 5) {
        return std::nullopt;
    }

    if (tokens[0] != "argon2id") {
        return std::nullopt;
    }

    ParsedPhc parsed;

    // Parse version (e.g. "v=19")
    if (!tokens[1].starts_with("v=")) {
        return std::nullopt;
    }
    auto v_str = tokens[1].substr(2);
    auto [v_ptr, v_ec] = std::from_chars(v_str.data(), v_str.data() + v_str.size(), parsed.version);
    if (v_ec != std::errc{} || v_ptr != v_str.data() + v_str.size()) {
        return std::nullopt;
    }
    if (parsed.version != 19 && parsed.version != 16) {
        return std::nullopt;
    }

    // Parse parameters: "m=65536,t=3,p=1"
    std::string_view param_str = tokens[2];
    bool has_m = false, has_t = false, has_p = false;
    std::size_t p_start = 0;
    while (p_start < param_str.size()) {
        std::size_t p_end = param_str.find(',', p_start);
        std::string_view item =
            (p_end == std::string_view::npos) ? param_str.substr(p_start) : param_str.substr(p_start, p_end - p_start);

        if (item.starts_with("m=")) {
            auto s = item.substr(2);
            auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), parsed.memory_cost_kib);
            if (ec != std::errc{} || ptr != s.data() + s.size())
                return std::nullopt;
            has_m = true;
        } else if (item.starts_with("t=")) {
            auto s = item.substr(2);
            auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), parsed.iterations);
            if (ec != std::errc{} || ptr != s.data() + s.size())
                return std::nullopt;
            has_t = true;
        } else if (item.starts_with("p=")) {
            auto s = item.substr(2);
            auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), parsed.parallelism);
            if (ec != std::errc{} || ptr != s.data() + s.size())
                return std::nullopt;
            has_p = true;
        } else {
            return std::nullopt;
        }

        if (p_end == std::string_view::npos)
            break;
        p_start = p_end + 1;
    }

    if (!has_m || !has_t || !has_p) {
        return std::nullopt;
    }

    // Sanity checks to prevent DoS / unbounded allocation
    if (parsed.memory_cost_kib < 8 || parsed.memory_cost_kib > 2097152) { // 8 KiB .. 2 GiB
        return std::nullopt;
    }
    if (parsed.iterations < 1 || parsed.iterations > 100) {
        return std::nullopt;
    }
    if (parsed.parallelism < 1 || parsed.parallelism > 64) {
        return std::nullopt;
    }

    // Decode salt
    auto decoded_salt = base64_decode_unpadded(tokens[3]);
    if (!decoded_salt.has_value() || decoded_salt->empty() || decoded_salt->size() > 128) {
        return std::nullopt;
    }
    parsed.salt = std::move(*decoded_salt);

    // Decode hash
    auto decoded_hash = base64_decode_unpadded(tokens[4]);
    if (!decoded_hash.has_value() || decoded_hash->size() < 16 || decoded_hash->size() > 128) {
        return std::nullopt;
    }
    parsed.hash = std::move(*decoded_hash);

    return parsed;
}

bool derive_argon2id(const std::string& password_str, const std::vector<std::uint8_t>& salt,
                     std::uint32_t memory_cost_kib, std::uint32_t iterations, std::uint32_t parallelism,
                     std::uint32_t version, std::vector<std::uint8_t>& out_key) {

    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
    if (kdf == nullptr) {
        return false;
    }

    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (kctx == nullptr) {
        return false;
    }

    OSSL_PARAM params[7];
    OSSL_PARAM* p = params;

    uint32_t iter = iterations;
    uint32_t lanes = parallelism;
    uint32_t memcost = memory_cost_kib;
    uint32_t ver = version;

    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter);
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes);
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memcost);
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_VERSION, &ver);

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<std::uint8_t*>(salt.data()), salt.size());

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, const_cast<char*>(password_str.data()),
                                             password_str.size());

    *p++ = OSSL_PARAM_construct_end();

    int ret = EVP_KDF_derive(kctx, out_key.data(), out_key.size(), params);
    EVP_KDF_CTX_free(kctx);

    return ret == 1;
}

} // namespace

OpenSslArgon2idHasher::OpenSslArgon2idHasher(Argon2idConfig config) : config_(config) {
    if (config_.memory_cost_kib < 8) {
        config_.memory_cost_kib = 8;
    }
    if (config_.iterations < 1) {
        config_.iterations = 1;
    }
    if (config_.parallelism < 1) {
        config_.parallelism = 1;
    }
    if (config_.salt_length < 8) {
        config_.salt_length = 8;
    }
    if (config_.hash_length < 16) {
        config_.hash_length = 16;
    }

    // Pre-generate a dummy verifier to ensure execute_dummy_verification()
    // performs exact computational work without overhead at request time.
    dummy_verifier_ =
        hash_password(common::configuration::SecretString("securecloud_dummy_enumeration_defense_secret"));
}

std::string OpenSslArgon2idHasher::hash_password(const common::configuration::SecretString& password) {
    std::vector<std::uint8_t> salt(config_.salt_length);
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
        throw std::runtime_error("OpenSSL RAND_bytes failed to generate salt for password hashing");
    }

    std::vector<std::uint8_t> derived(config_.hash_length);
    const std::string& pwd_str = password.expose_unredacted_secret();

    bool success = derive_argon2id(pwd_str, salt, config_.memory_cost_kib, config_.iterations, config_.parallelism,
                                   19, // version 0x13
                                   derived);

    if (!success) {
        OPENSSL_cleanse(derived.data(), derived.size());
        throw std::runtime_error("OpenSSL EVP_KDF derivation failed for Argon2id");
    }

    std::string salt_b64 = base64_encode_unpadded(salt.data(), salt.size());
    std::string hash_b64 = base64_encode_unpadded(derived.data(), derived.size());

    OPENSSL_cleanse(derived.data(), derived.size());

    std::ostringstream ss;
    ss << "$argon2id$v=19$m=" << config_.memory_cost_kib << ",t=" << config_.iterations << ",p=" << config_.parallelism
       << "$" << salt_b64 << "$" << hash_b64;

    return ss.str();
}

bool OpenSslArgon2idHasher::verify_password(const common::configuration::SecretString& password,
                                            std::string_view stored_verifier) {

    auto parsed = parse_phc_verifier(stored_verifier);
    if (!parsed.has_value()) {
        return false;
    }

    std::vector<std::uint8_t> candidate_hash(parsed->hash.size());
    const std::string& pwd_str = password.expose_unredacted_secret();

    bool derived_ok = derive_argon2id(pwd_str, parsed->salt, parsed->memory_cost_kib, parsed->iterations,
                                      parsed->parallelism, parsed->version, candidate_hash);

    if (!derived_ok) {
        OPENSSL_cleanse(candidate_hash.data(), candidate_hash.size());
        return false;
    }

    // Constant-time memory comparison to defend against timing side-channels
    int diff = CRYPTO_memcmp(candidate_hash.data(), parsed->hash.data(), candidate_hash.size());
    OPENSSL_cleanse(candidate_hash.data(), candidate_hash.size());

    return (diff == 0);
}

void OpenSslArgon2idHasher::execute_dummy_verification(const common::configuration::SecretString& password) {
    (void)verify_password(password, dummy_verifier_);
}

} // namespace securecloud::auth::crypto
