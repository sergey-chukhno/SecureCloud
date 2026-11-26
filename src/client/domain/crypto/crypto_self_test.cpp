#include "domain/crypto/crypto_self_test.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <memory>
#include <nlohmann/json.hpp>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <utility>

namespace securecloud::client::domain::crypto {
namespace {

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* ptr) const noexcept {
        if (ptr != nullptr) {
            EVP_PKEY_free(ptr);
        }
    }
};

struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* ptr) const noexcept {
        if (ptr != nullptr) {
            EVP_PKEY_CTX_free(ptr);
        }
    }
};

struct EvpMdCtxDeleter {
    void operator()(EVP_MD_CTX* ptr) const noexcept {
        if (ptr != nullptr) {
            EVP_MD_CTX_free(ptr);
        }
    }
};

struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ptr) const noexcept {
        if (ptr != nullptr) {
            EVP_CIPHER_CTX_free(ptr);
        }
    }
};

struct EvpKdfDeleter {
    void operator()(EVP_KDF* ptr) const noexcept {
        if (ptr != nullptr) {
            EVP_KDF_free(ptr);
        }
    }
};

struct EvpKdfCtxDeleter {
    void operator()(EVP_KDF_CTX* ptr) const noexcept {
        if (ptr != nullptr) {
            EVP_KDF_CTX_free(ptr);
        }
    }
};

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;
using EvpKdfPtr = std::unique_ptr<EVP_KDF, EvpKdfDeleter>;
using EvpKdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, EvpKdfCtxDeleter>;

[[nodiscard]] int64_t current_unix_ms() noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

[[nodiscard]] int64_t elapsed_us(std::chrono::steady_clock::time_point start) noexcept {
    const auto us =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();
    return us >= 0 ? us : 0;
}

[[nodiscard]] std::optional<uint8_t> hex_nibble(char ch) noexcept {
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

[[nodiscard]] std::vector<uint8_t> decode_hex(std::string_view hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2U);
    for (std::size_t i = 0; i + 1U < hex.size(); i += 2U) {
        const auto hi = hex_nibble(hex[i]);
        const auto lo = hex_nibble(hex[i + 1U]);
        if (!hi.has_value() || !lo.has_value()) {
            return {};
        }
        out.push_back(static_cast<uint8_t>((static_cast<unsigned int>(*hi) << 4U) | static_cast<unsigned int>(*lo)));
    }
    return out;
}

[[nodiscard]] std::string encode_hex(const uint8_t* data, std::size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2U);
    for (std::size_t i = 0; i < len; ++i) {
        const uint8_t b = data[i];
        out.push_back(kHex[(b >> 4U) & 0x0FU]);
        out.push_back(kHex[b & 0x0FU]);
    }
    return out;
}

[[nodiscard]] std::string consume_openssl_error() {
    char buf[256];
    const unsigned long err = ERR_get_error();
    ERR_clear_error();
    if (err == 0UL) {
        return "OpenSSL error unavailable";
    }
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

[[nodiscard]] std::optional<std::string> check_injected_fault(const CryptoSelfTest::FaultInjector& injector,
                                                              std::string_view check_name) {
    if (!injector) {
        return std::nullopt;
    }
    const auto fault = injector(check_name);
    if (fault.has_value() && !fault->empty()) {
        return fault;
    }
    if (fault.has_value()) {
        return std::string("Injected cryptographic self-test fault");
    }
    return std::nullopt;
}

[[nodiscard]] CryptoSelfTestCheckResult finish_check(std::string_view check_name, bool passed, std::string detail,
                                                     std::chrono::steady_clock::time_point start) {
    CryptoSelfTestCheckResult result;
    result.check_name = std::string(check_name);
    result.passed = passed;
    result.detail = std::move(detail);
    result.duration_us = elapsed_us(start);
    return result;
}

} // namespace

std::string CryptoSelfTestReport::to_json() const {
    nlohmann::json root;
    root["overall_passed"] = overall_passed;
    root["total_duration_us"] = total_duration_us;
    root["executed_at_ms"] = executed_at_ms;
    root["crypto_backend"] = crypto_backend;

    nlohmann::json check_array = nlohmann::json::array();
    for (const auto& check : checks) {
        nlohmann::json item;
        item["check_name"] = check.check_name;
        item["passed"] = check.passed;
        item["detail"] = check.detail;
        item["duration_us"] = check.duration_us;
        check_array.push_back(std::move(item));
    }
    root["checks"] = std::move(check_array);
    return root.dump();
}

std::string CryptoSelfTestReport::failed_checks_summary() const {
    std::string summary;
    for (const auto& check : checks) {
        if (!check.passed) {
            if (!summary.empty()) {
                summary += ", ";
            }
            summary += check.check_name;
        }
    }
    if (summary.empty() && !overall_passed) {
        return "unknown";
    }
    return summary;
}

CryptoSelfTestCheckResult CryptoSelfTest::run_ed25519_kat(const FaultInjector& fault_injector) {
    constexpr std::string_view kName = "ed25519_kat";
    const auto start = std::chrono::steady_clock::now();

    if (const auto fault = check_injected_fault(fault_injector, kName); fault.has_value()) {
        return finish_check(kName, false, *fault, start);
    }

    // RFC 8032 Section 7.1 TEST 1 (empty message)
    const auto seed = decode_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    const auto expected_pub = decode_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const auto expected_sig = decode_hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                                         "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

    EvpPkeyPtr priv_pkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size()));
    if (!priv_pkey) {
        return finish_check(kName, false, "EVP_PKEY_new_raw_private_key failed: " + consume_openssl_error(), start);
    }

    std::array<uint8_t, 32> actual_pub{};
    std::size_t pub_len = actual_pub.size();
    if (EVP_PKEY_get_raw_public_key(priv_pkey.get(), actual_pub.data(), &pub_len) != 1 || pub_len != 32U) {
        return finish_check(kName, false, "EVP_PKEY_get_raw_public_key failed: " + consume_openssl_error(), start);
    }
    if (CRYPTO_memcmp(actual_pub.data(), expected_pub.data(), expected_pub.size()) != 0) {
        return finish_check(kName, false, "Ed25519 public key derivation mismatch against RFC 8032 vector #1", start);
    }

    std::array<uint8_t, 64> sig{};
    std::size_t sig_len = sig.size();
    const uint8_t empty_msg = 0U;
    {
        EvpMdCtxPtr sctx(EVP_MD_CTX_new());
        if (!sctx || EVP_DigestSignInit(sctx.get(), nullptr, nullptr, nullptr, priv_pkey.get()) != 1 ||
            EVP_DigestSign(sctx.get(), sig.data(), &sig_len, &empty_msg, 0U) != 1 || sig_len != 64U) {
            return finish_check(kName, false, "Ed25519 signing failed: " + consume_openssl_error(), start);
        }
    }
    if (CRYPTO_memcmp(sig.data(), expected_sig.data(), expected_sig.size()) != 0) {
        return finish_check(kName, false, "Ed25519 signature mismatch against RFC 8032 vector #1", start);
    }

    EvpPkeyPtr pub_pkey(
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, expected_pub.data(), expected_pub.size()));
    if (!pub_pkey) {
        return finish_check(kName, false, "EVP_PKEY_new_raw_public_key failed: " + consume_openssl_error(), start);
    }

    {
        EvpMdCtxPtr vctx(EVP_MD_CTX_new());
        if (!vctx || EVP_DigestVerifyInit(vctx.get(), nullptr, nullptr, nullptr, pub_pkey.get()) != 1 ||
            EVP_DigestVerify(vctx.get(), sig.data(), sig.size(), &empty_msg, 0U) != 1) {
            return finish_check(kName, false, "Ed25519 signature verification failed: " + consume_openssl_error(),
                                start);
        }
    }

    // 1-bit flipped signature MUST fail verification.
    sig[0] ^= 0x01U;
    {
        EvpMdCtxPtr vctx_tamper(EVP_MD_CTX_new());
        if (!vctx_tamper || EVP_DigestVerifyInit(vctx_tamper.get(), nullptr, nullptr, nullptr, pub_pkey.get()) != 1) {
            return finish_check(kName, false, "Ed25519 tamper verify init failed: " + consume_openssl_error(), start);
        }
        const int verify_rc = EVP_DigestVerify(vctx_tamper.get(), sig.data(), sig.size(), &empty_msg, 0U);
        ERR_clear_error();
        if (verify_rc == 1) {
            return finish_check(kName, false, "Ed25519 accepted 1-bit tampered signature", start);
        }
    }

    return finish_check(kName, true, "RFC 8032 Test Vector #1 sign/verify/tamper-reject passed", start);
}

CryptoSelfTestCheckResult CryptoSelfTest::run_x25519_kat(const FaultInjector& fault_injector) {
    constexpr std::string_view kName = "x25519_kat";
    const auto start = std::chrono::steady_clock::now();

    if (const auto fault = check_injected_fault(fault_injector, kName); fault.has_value()) {
        return finish_check(kName, false, *fault, start);
    }

    // RFC 7748 Section 6.1 test vector
    const auto alice_priv = decode_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const auto expected_alice_pub = decode_hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    const auto bob_pub = decode_hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const auto expected_secret = decode_hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    EvpPkeyPtr alice_pkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, alice_priv.data(), alice_priv.size()));
    if (!alice_pkey) {
        return finish_check(kName, false, "Failed to import X25519 private key: " + consume_openssl_error(), start);
    }

    std::array<uint8_t, 32> actual_alice_pub{};
    std::size_t pub_len = actual_alice_pub.size();
    if (EVP_PKEY_get_raw_public_key(alice_pkey.get(), actual_alice_pub.data(), &pub_len) != 1 || pub_len != 32U) {
        return finish_check(kName, false, "Failed to extract X25519 public key: " + consume_openssl_error(), start);
    }
    if (CRYPTO_memcmp(actual_alice_pub.data(), expected_alice_pub.data(), expected_alice_pub.size()) != 0) {
        return finish_check(kName, false, "X25519 public key mismatch against RFC 7748 vector", start);
    }

    EvpPkeyPtr bob_pkey(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, bob_pub.data(), bob_pub.size()));
    if (!bob_pkey) {
        return finish_check(kName, false, "Failed to import X25519 peer public key: " + consume_openssl_error(), start);
    }

    EvpPkeyCtxPtr dctx(EVP_PKEY_CTX_new(alice_pkey.get(), nullptr));
    if (!dctx || EVP_PKEY_derive_init(dctx.get()) <= 0 || EVP_PKEY_derive_set_peer(dctx.get(), bob_pkey.get()) <= 0) {
        return finish_check(kName, false, "X25519 derive initialization failed: " + consume_openssl_error(), start);
    }

    std::array<uint8_t, 32> shared_secret{};
    std::size_t secret_len = shared_secret.size();
    if (EVP_PKEY_derive(dctx.get(), shared_secret.data(), &secret_len) <= 0 || secret_len != 32U) {
        OPENSSL_cleanse(shared_secret.data(), shared_secret.size());
        return finish_check(kName, false, "X25519 EVP_PKEY_derive failed: " + consume_openssl_error(), start);
    }

    const bool matched = (CRYPTO_memcmp(shared_secret.data(), expected_secret.data(), expected_secret.size()) == 0);
    OPENSSL_cleanse(shared_secret.data(), shared_secret.size());
    if (!matched) {
        return finish_check(kName, false, "X25519 shared secret mismatch against RFC 7748 vector", start);
    }

    return finish_check(kName, true, "RFC 7748 X25519 key derivation vector matched", start);
}

CryptoSelfTestCheckResult CryptoSelfTest::run_aes_256_gcm_kat(const FaultInjector& fault_injector) {
    constexpr std::string_view kName = "aes_256_gcm_kat";
    const auto start = std::chrono::steady_clock::now();

    if (const auto fault = check_injected_fault(fault_injector, kName); fault.has_value()) {
        return finish_check(kName, false, *fault, start);
    }

    // NIST SP 800-38D Test Case 16 (256-bit key, 96-bit IV, 20-byte AAD, 60-byte PT)
    const auto key = decode_hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    const auto iv = decode_hex("cafebabefacedbaddecaf888");
    const auto aad = decode_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    const auto pt = decode_hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                               "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
    const auto expected_ct = decode_hex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                                        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662");
    const auto expected_tag = decode_hex("76fc6ece0f4e1768cddf8853bb2d551b");

    std::vector<uint8_t> ct(pt.size(), 0U);
    std::array<uint8_t, 16> tag{};
    {
        EvpCipherCtxPtr ectx(EVP_CIPHER_CTX_new());
        int out_len = 0;
        int final_len = 0;
        if (!ectx || EVP_EncryptInit_ex(ectx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ectx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1 ||
            EVP_EncryptInit_ex(ectx.get(), nullptr, nullptr, key.data(), iv.data()) != 1 ||
            EVP_EncryptUpdate(ectx.get(), nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1 ||
            EVP_EncryptUpdate(ectx.get(), ct.data(), &out_len, pt.data(), static_cast<int>(pt.size())) != 1 ||
            EVP_EncryptFinal_ex(ectx.get(), ct.data() + out_len, &final_len) != 1 ||
            EVP_CIPHER_CTX_ctrl(ectx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
            return finish_check(kName, false, "AES-256-GCM encryption failed: " + consume_openssl_error(), start);
        }
        if (static_cast<std::size_t>(out_len + final_len) != expected_ct.size() ||
            CRYPTO_memcmp(ct.data(), expected_ct.data(), expected_ct.size()) != 0 ||
            CRYPTO_memcmp(tag.data(), expected_tag.data(), expected_tag.size()) != 0) {
            return finish_check(kName, false, "AES-256-GCM ciphertext or auth tag mismatch against NIST Test Case 16",
                                start);
        }
    }

    // Decrypt valid vector
    {
        EvpCipherCtxPtr dctx(EVP_CIPHER_CTX_new());
        std::vector<uint8_t> recovered(ct.size(), 0U);
        int out_len = 0;
        int final_len = 0;
        if (!dctx || EVP_DecryptInit_ex(dctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(dctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1 ||
            EVP_DecryptInit_ex(dctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1 ||
            EVP_DecryptUpdate(dctx.get(), nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1 ||
            EVP_DecryptUpdate(dctx.get(), recovered.data(), &out_len, ct.data(), static_cast<int>(ct.size())) != 1 ||
            EVP_CIPHER_CTX_ctrl(dctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag.data()) != 1 ||
            EVP_DecryptFinal_ex(dctx.get(), recovered.data() + out_len, &final_len) != 1) {
            OPENSSL_cleanse(recovered.data(), recovered.size());
            return finish_check(kName, false, "AES-256-GCM decryption failed: " + consume_openssl_error(), start);
        }
        const bool pt_ok = (CRYPTO_memcmp(recovered.data(), pt.data(), pt.size()) == 0);
        OPENSSL_cleanse(recovered.data(), recovered.size());
        if (!pt_ok) {
            return finish_check(kName, false, "AES-256-GCM decrypted plaintext mismatch", start);
        }
    }

    // 1-bit flipped auth tag MUST fail EVP_DecryptFinal_ex
    tag[0] ^= 0x01U;
    {
        EvpCipherCtxPtr dctx_tamper(EVP_CIPHER_CTX_new());
        std::vector<uint8_t> recovered(ct.size(), 0U);
        int out_len = 0;
        int final_len = 0;
        if (!dctx_tamper || EVP_DecryptInit_ex(dctx_tamper.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(dctx_tamper.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1 ||
            EVP_DecryptInit_ex(dctx_tamper.get(), nullptr, nullptr, key.data(), iv.data()) != 1 ||
            EVP_DecryptUpdate(dctx_tamper.get(), nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1 ||
            EVP_DecryptUpdate(dctx_tamper.get(), recovered.data(), &out_len, ct.data(), static_cast<int>(ct.size())) !=
                1 ||
            EVP_CIPHER_CTX_ctrl(dctx_tamper.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag.data()) !=
                1) {
            OPENSSL_cleanse(recovered.data(), recovered.size());
            return finish_check(kName, false, "AES-256-GCM tamper test setup failed: " + consume_openssl_error(),
                                start);
        }
        const int final_rc = EVP_DecryptFinal_ex(dctx_tamper.get(), recovered.data() + out_len, &final_len);
        ERR_clear_error();
        OPENSSL_cleanse(recovered.data(), recovered.size());
        if (final_rc == 1) {
            return finish_check(kName, false, "AES-256-GCM accepted 1-bit tampered authentication tag", start);
        }
    }

    return finish_check(kName, true, "NIST SP 800-38D AES-256-GCM KAT and tag tamper detection passed", start);
}

CryptoSelfTestCheckResult CryptoSelfTest::run_hkdf_sha256_kat(const FaultInjector& fault_injector) {
    constexpr std::string_view kName = "hkdf_sha256_kat";
    const auto start = std::chrono::steady_clock::now();

    if (const auto fault = check_injected_fault(fault_injector, kName); fault.has_value()) {
        return finish_check(kName, false, *fault, start);
    }

    // RFC 5869 Appendix A.1 Test Case 1
    auto ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    auto salt = decode_hex("000102030405060708090a0b0c");
    auto info = decode_hex("f0f1f2f3f4f5f6f7f8f9");
    const auto expected_okm =
        decode_hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

    EvpKdfPtr kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    if (!kdf) {
        return finish_check(kName, false, "EVP_KDF_fetch(HKDF) failed: " + consume_openssl_error(), start);
    }
    EvpKdfCtxPtr kctx(EVP_KDF_CTX_new(kdf.get()));
    if (!kctx) {
        return finish_check(kName, false, "EVP_KDF_CTX_new(HKDF) failed: " + consume_openssl_error(), start);
    }

    char md_name[] = "SHA256";
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    OSSL_PARAM params[6];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, md_name, 0U);
    params[1] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm.data(), ikm.size());
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt.data(), salt.size());
    params[4] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info.data(), info.size());
    params[5] = OSSL_PARAM_construct_end();

    std::vector<uint8_t> okm(expected_okm.size(), 0U);
    const int derive_rc = EVP_KDF_derive(kctx.get(), okm.data(), okm.size(), params);
    if (derive_rc <= 0) {
        OPENSSL_cleanse(okm.data(), okm.size());
        return finish_check(kName, false, "EVP_KDF_derive(HKDF) failed: " + consume_openssl_error(), start);
    }

    const bool matched = (CRYPTO_memcmp(okm.data(), expected_okm.data(), expected_okm.size()) == 0);
    OPENSSL_cleanse(okm.data(), okm.size());
    if (!matched) {
        return finish_check(kName, false, "HKDF-SHA256 OKM mismatch against RFC 5869 Case 1", start);
    }

    return finish_check(kName, true, "RFC 5869 Case 1 HKDF-SHA256 derivation vector matched", start);
}

CryptoSelfTestCheckResult CryptoSelfTest::run_csprng_health_check(const FaultInjector& fault_injector) {
    constexpr std::string_view kName = "csprng_health";
    const auto start = std::chrono::steady_clock::now();

    if (const auto fault = check_injected_fault(fault_injector, kName); fault.has_value()) {
        return finish_check(kName, false, *fault, start);
    }

    if (RAND_status() != 1) {
        return finish_check(kName, false, "OpenSSL CSPRNG reported insufficient entropy (RAND_status != 1)", start);
    }

    std::array<uint8_t, 32> sample{};
    if (RAND_bytes(sample.data(), static_cast<int>(sample.size())) != 1) {
        OPENSSL_cleanse(sample.data(), sample.size());
        return finish_check(kName, false, "RAND_bytes failed: " + consume_openssl_error(), start);
    }

    const bool all_zero = std::all_of(sample.begin(), sample.end(), [](uint8_t b) { return b == 0U; });
    const bool all_equal = std::all_of(sample.begin(), sample.end(), [&](uint8_t b) { return b == sample[0]; });
    OPENSSL_cleanse(sample.data(), sample.size());

    if (all_zero || all_equal) {
        return finish_check(kName, false, "CSPRNG produced degenerate constant output", start);
    }

    return finish_check(kName, true, "RAND_status == 1 and 32-byte CSPRNG sample entropy verified", start);
}

CryptoSelfTestCheckResult
CryptoSelfTest::run_secure_storage_canary(application::interfaces::ISecureStorage* secure_storage,
                                          const FaultInjector& fault_injector) {
    constexpr std::string_view kName = "secure_storage_canary";
    const auto start = std::chrono::steady_clock::now();

    if (const auto fault = check_injected_fault(fault_injector, kName); fault.has_value()) {
        return finish_check(kName, false, *fault, start);
    }
    if (secure_storage == nullptr) {
        return finish_check(kName, false, "ISecureStorage instance is null", start);
    }

    std::array<uint8_t, 16> raw_canary{};
    if (RAND_bytes(raw_canary.data(), static_cast<int>(raw_canary.size())) != 1) {
        OPENSSL_cleanse(raw_canary.data(), raw_canary.size());
        return finish_check(kName, false, "Failed to generate CSPRNG canary value", start);
    }
    std::string expected_hex = encode_hex(raw_canary.data(), raw_canary.size());
    OPENSSL_cleanse(raw_canary.data(), raw_canary.size());

    const auto store_res =
        secure_storage->store_secret(kCanaryStorageKey, common::configuration::SecretString(expected_hex));
    if (store_res.is_error()) {
        OPENSSL_cleanse(expected_hex.data(), expected_hex.size());
        return finish_check(kName, false, "ISecureStorage store_secret failed: " + store_res.error().user_message(),
                            start);
    }

    const auto get_res = secure_storage->get_secret(kCanaryStorageKey);
    if (get_res.is_error()) {
        (void)secure_storage->delete_secret(kCanaryStorageKey);
        OPENSSL_cleanse(expected_hex.data(), expected_hex.size());
        return finish_check(kName, false, "ISecureStorage get_secret failed: " + get_res.error().user_message(), start);
    }

    const std::string& actual_hex = get_res.value().expose_unredacted_secret();
    const bool equal = (actual_hex.size() == expected_hex.size()) &&
                       (CRYPTO_memcmp(actual_hex.data(), expected_hex.data(), expected_hex.size()) == 0);
    OPENSSL_cleanse(expected_hex.data(), expected_hex.size());

    const auto del_res = secure_storage->delete_secret(kCanaryStorageKey);
    if (!equal) {
        return finish_check(kName, false, "ISecureStorage canary readback value mismatch", start);
    }
    if (del_res.is_error()) {
        return finish_check(kName, false, "ISecureStorage delete_secret failed: " + del_res.error().user_message(),
                            start);
    }

    const auto has_res = secure_storage->has_secret(kCanaryStorageKey);
    if (has_res.is_error() || has_res.value()) {
        return finish_check(kName, false, "ISecureStorage canary key remained present after deletion", start);
    }

    return finish_check(kName, true, "ISecureStorage write/readback/delete round-trip verified", start);
}

CryptoSelfTestReport CryptoSelfTest::run_all(application::interfaces::ISecureStorage* secure_storage,
                                             const FaultInjector& fault_injector) {
    const auto suite_start = std::chrono::steady_clock::now();

    CryptoSelfTestReport report;
    report.executed_at_ms = current_unix_ms();
    report.crypto_backend = OpenSSL_version(OPENSSL_VERSION);
    report.checks.reserve(6U);

    report.checks.push_back(run_ed25519_kat(fault_injector));
    report.checks.push_back(run_x25519_kat(fault_injector));
    report.checks.push_back(run_aes_256_gcm_kat(fault_injector));
    report.checks.push_back(run_hkdf_sha256_kat(fault_injector));
    report.checks.push_back(run_csprng_health_check(fault_injector));
    report.checks.push_back(run_secure_storage_canary(secure_storage, fault_injector));

    report.total_duration_us = elapsed_us(suite_start);
    report.overall_passed = std::all_of(report.checks.begin(), report.checks.end(),
                                        [](const CryptoSelfTestCheckResult& c) { return c.passed; });

    return report;
}

} // namespace securecloud::client::domain::crypto
