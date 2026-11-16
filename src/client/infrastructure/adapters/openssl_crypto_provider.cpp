#include "infrastructure/adapters/openssl_crypto_provider.hpp"

#include "domain/prekey_policy.hpp"

#include <algorithm>
#include <array>
#include <iomanip>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <sstream>
#include <string>

namespace securecloud::client::infrastructure::adapters {

namespace {

std::string get_openssl_error_string() {
    char buf[256];
    const unsigned long err = ERR_get_error();
    if (err == 0) {
        return "Unknown OpenSSL error";
    }
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

application::ClientResult<std::pair<std::vector<uint8_t>, securecloud::common::configuration::SecretString>>
generate_raw_evp_keypair(int evp_pkey_type, std::size_t expected_size) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(evp_pkey_type, nullptr);
    if (!pctx) {
        return application::
            ClientResult<std::pair<std::vector<uint8_t>, securecloud::common::configuration::SecretString>>::error(
                application::ClientError::crypto("OpenSSL EVP_PKEY_CTX_new_id failed: " + get_openssl_error_string()));
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return application::
            ClientResult<std::pair<std::vector<uint8_t>, securecloud::common::configuration::SecretString>>::error(
                application::ClientError::crypto("OpenSSL EVP_PKEY_keygen_init failed: " + get_openssl_error_string()));
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0 || !pkey) {
        EVP_PKEY_CTX_free(pctx);
        return application::
            ClientResult<std::pair<std::vector<uint8_t>, securecloud::common::configuration::SecretString>>::error(
                application::ClientError::crypto("OpenSSL EVP_PKEY_keygen failed: " + get_openssl_error_string()));
    }
    EVP_PKEY_CTX_free(pctx);

    std::vector<uint8_t> public_key(expected_size);
    std::size_t pub_len = public_key.size();
    if (EVP_PKEY_get_raw_public_key(pkey, public_key.data(), &pub_len) <= 0 || pub_len != expected_size) {
        EVP_PKEY_free(pkey);
        return application::
            ClientResult<std::pair<std::vector<uint8_t>, securecloud::common::configuration::SecretString>>::error(
                application::ClientError::crypto("Failed to extract raw public key: " + get_openssl_error_string()));
    }

    std::vector<uint8_t> priv_buf(expected_size);
    std::size_t priv_len = priv_buf.size();
    if (EVP_PKEY_get_raw_private_key(pkey, priv_buf.data(), &priv_len) <= 0 || priv_len != expected_size) {
        EVP_PKEY_free(pkey);
        OPENSSL_cleanse(priv_buf.data(), priv_buf.size());
        return application::
            ClientResult<std::pair<std::vector<uint8_t>, securecloud::common::configuration::SecretString>>::error(
                application::ClientError::crypto("Failed to extract raw private key: " + get_openssl_error_string()));
    }
    EVP_PKEY_free(pkey);

    std::string priv_str(reinterpret_cast<const char*>(priv_buf.data()), priv_buf.size());
    OPENSSL_cleanse(priv_buf.data(), priv_buf.size());

    return application::
        ClientResult<std::pair<std::vector<uint8_t>, securecloud::common::configuration::SecretString>>::ok(
            std::make_pair(std::move(public_key),
                           securecloud::common::configuration::SecretString(std::move(priv_str))));
}

} // namespace

application::ClientResult<application::interfaces::IdentityKeyPair> OpenSslCryptoProvider::generate_identity_keypair() {
    auto key_res = generate_raw_evp_keypair(EVP_PKEY_ED25519, domain::PrekeyPolicy::kEd25519PublicKeySize);
    if (!key_res.is_ok()) {
        return application::ClientResult<application::interfaces::IdentityKeyPair>::error(key_res.error());
    }

    auto [pub, priv] = std::move(key_res).value();
    return application::ClientResult<application::interfaces::IdentityKeyPair>::ok(
        application::interfaces::IdentityKeyPair{
            .public_key = std::move(pub),
            .private_key = std::move(priv),
        });
}

application::ClientResult<application::interfaces::SignedPrekeyResult> OpenSslCryptoProvider::generate_signed_prekey(
    const securecloud::common::configuration::SecretString& identity_private_key) {
    if (identity_private_key.size() != domain::PrekeyPolicy::kEd25519PrivateKeySize) {
        return application::ClientResult<application::interfaces::SignedPrekeyResult>::error(
            application::ClientError::crypto("Identity private key must be exactly " +
                                             std::to_string(domain::PrekeyPolicy::kEd25519PrivateKeySize) + " bytes"));
    }

    // 1. Generate X25519 prekey pair
    auto spk_res = generate_raw_evp_keypair(EVP_PKEY_X25519, domain::PrekeyPolicy::kX25519PublicKeySize);
    if (!spk_res.is_ok()) {
        return application::ClientResult<application::interfaces::SignedPrekeyResult>::error(spk_res.error());
    }
    auto [spk_pub, spk_priv] = std::move(spk_res).value();

    // 2. Sign X25519 public key using Ed25519 identity private key
    const auto& priv_bytes = identity_private_key.expose_unredacted_secret();
    EVP_PKEY* id_pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char*>(priv_bytes.data()), priv_bytes.size());
    if (!id_pkey) {
        return application::ClientResult<application::interfaces::SignedPrekeyResult>::error(
            application::ClientError::crypto("Failed to import Ed25519 private key: " + get_openssl_error_string()));
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(id_pkey);
        return application::ClientResult<application::interfaces::SignedPrekeyResult>::error(
            application::ClientError::crypto("Failed to allocate EVP_MD_CTX for signing"));
    }

    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, id_pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(id_pkey);
        return application::ClientResult<application::interfaces::SignedPrekeyResult>::error(
            application::ClientError::crypto("EVP_DigestSignInit failed: " + get_openssl_error_string()));
    }

    std::vector<uint8_t> signature(domain::PrekeyPolicy::kEd25519SignatureSize);
    std::size_t sig_len = signature.size();
    if (EVP_DigestSign(ctx, signature.data(), &sig_len, spk_pub.data(), spk_pub.size()) <= 0 ||
        sig_len != domain::PrekeyPolicy::kEd25519SignatureSize) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(id_pkey);
        return application::ClientResult<application::interfaces::SignedPrekeyResult>::error(
            application::ClientError::crypto("EVP_DigestSign failed: " + get_openssl_error_string()));
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(id_pkey);

    return application::ClientResult<application::interfaces::SignedPrekeyResult>::ok(
        application::interfaces::SignedPrekeyResult{
            .public_key = std::move(spk_pub),
            .private_key = std::move(spk_priv),
            .signature = std::move(signature),
        });
}

application::ClientResult<bool>
OpenSslCryptoProvider::verify_signed_prekey(std::span<const uint8_t> identity_public_key,
                                            std::span<const uint8_t> signed_prekey_public_key,
                                            std::span<const uint8_t> signature) {
    if (identity_public_key.size() != domain::PrekeyPolicy::kEd25519PublicKeySize ||
        signed_prekey_public_key.size() != domain::PrekeyPolicy::kX25519PublicKeySize ||
        signature.size() != domain::PrekeyPolicy::kEd25519SignatureSize) {
        return application::ClientResult<bool>::ok(false);
    }

    EVP_PKEY* id_pkey =
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, identity_public_key.data(), identity_public_key.size());
    if (!id_pkey) {
        return application::ClientResult<bool>::ok(false);
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(id_pkey);
        return application::ClientResult<bool>::error(
            application::ClientError::crypto("Failed to allocate EVP_MD_CTX for verification"));
    }

    bool verified = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, id_pkey) == 1) {
        if (EVP_DigestVerify(ctx, signature.data(), signature.size(), signed_prekey_public_key.data(),
                             signed_prekey_public_key.size()) == 1) {
            verified = true;
        }
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(id_pkey);

    return application::ClientResult<bool>::ok(verified);
}

application::ClientResult<std::vector<application::interfaces::OneTimePrekeyPair>>
OpenSslCryptoProvider::generate_one_time_prekeys(std::size_t count, std::size_t start_index) {
    std::vector<application::interfaces::OneTimePrekeyPair> result;
    result.reserve(count);

    for (std::size_t i = 0; i < count; ++i) {
        auto key_res = generate_raw_evp_keypair(EVP_PKEY_X25519, domain::PrekeyPolicy::kX25519PublicKeySize);
        if (!key_res.is_ok()) {
            return application::ClientResult<std::vector<application::interfaces::OneTimePrekeyPair>>::error(
                key_res.error());
        }
        auto [pub, priv] = std::move(key_res).value();
        result.push_back(application::interfaces::OneTimePrekeyPair{
            .record = domain::OneTimePrekeyRecord(std::to_string(start_index + i), std::move(pub)),
            .private_key = std::move(priv),
        });
    }

    return application::ClientResult<std::vector<application::interfaces::OneTimePrekeyPair>>::ok(std::move(result));
}

application::ClientResult<std::string>
OpenSslCryptoProvider::compute_identity_fingerprint(std::span<const uint8_t> identity_public_key) {
    if (identity_public_key.empty()) {
        return application::ClientResult<std::string>::error(
            application::ClientError::crypto("Identity public key cannot be empty"));
    }

    std::vector<uint8_t> digest(32);
    unsigned int md_len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return application::ClientResult<std::string>::error(
            application::ClientError::crypto("Failed to allocate OpenSSL EVP_MD_CTX for fingerprint"));
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, identity_public_key.data(), identity_public_key.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, digest.data(), &md_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return application::ClientResult<std::string>::error(
            application::ClientError::crypto("OpenSSL SHA-256 fingerprint digest computation failed"));
    }

    EVP_MD_CTX_free(ctx);
    digest.resize(md_len);

    constexpr char hex_chars[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(7 + (digest.size() * 3) - 1);
    result.append("SHA256:");

    for (std::size_t i = 0; i < digest.size(); ++i) {
        if (i > 0) {
            result.push_back(':');
        }
        result.push_back(hex_chars[(digest[i] >> 4) & 0x0F]);
        result.push_back(hex_chars[digest[i] & 0x0F]);
    }

    return application::ClientResult<std::string>::ok(std::move(result));
}

application::ClientResult<securecloud::common::configuration::SecretString>
derive_hkdf(int mode, std::span<const uint8_t> salt, const void* key_data, std::size_t key_len,
            std::span<const uint8_t> info, std::size_t out_len) {
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Failed to fetch OpenSSL HKDF: " + get_openssl_error_string()));
    }

    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Failed to create OpenSSL HKDF CTX: " + get_openssl_error_string()));
    }

    OSSL_PARAM params[6];
    std::size_t p_idx = 0;

    char md_name[] = "SHA256";
    params[p_idx++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, md_name, 0);
    params[p_idx++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);

    if (key_data && key_len > 0) {
        params[p_idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<void*>(key_data), key_len);
    }
    if (!salt.empty()) {
        params[p_idx++] =
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<uint8_t*>(salt.data()), salt.size());
    }
    if (!info.empty()) {
        params[p_idx++] =
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<uint8_t*>(info.data()), info.size());
    }
    params[p_idx] = OSSL_PARAM_construct_end();

    std::vector<uint8_t> out_buf(out_len, 0);
    if (EVP_KDF_derive(kctx, out_buf.data(), out_buf.size(), params) <= 0) {
        OPENSSL_cleanse(out_buf.data(), out_buf.size());
        EVP_KDF_CTX_free(kctx);
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("OpenSSL HKDF derivation failed: " + get_openssl_error_string()));
    }

    EVP_KDF_CTX_free(kctx);

    std::string out_str(reinterpret_cast<const char*>(out_buf.data()), out_buf.size());
    OPENSSL_cleanse(out_buf.data(), out_buf.size());

    return application::ClientResult<securecloud::common::configuration::SecretString>::ok(
        securecloud::common::configuration::SecretString(std::move(out_str)));
}

application::ClientResult<domain::CryptoIdentity> OpenSslCryptoProvider::generate_device_identity() {
    auto id_res = generate_identity_keypair();
    if (!id_res.is_ok()) {
        return application::ClientResult<domain::CryptoIdentity>::error(id_res.error());
    }
    auto id_pair = std::move(id_res).value();

    auto fp_res = compute_identity_fingerprint(id_pair.public_key);
    if (!fp_res.is_ok()) {
        return application::ClientResult<domain::CryptoIdentity>::error(fp_res.error());
    }

    auto spk_res = generate_signed_prekey(id_pair.private_key);
    if (!spk_res.is_ok()) {
        return application::ClientResult<domain::CryptoIdentity>::error(spk_res.error());
    }
    auto spk_result = std::move(spk_res).value();

    domain::CryptoIdentity identity(id_pair.public_key, fp_res.value(), domain::KeyVerificationStatus::Verified,
                                    spk_result.public_key, spk_result.signature);
    return application::ClientResult<domain::CryptoIdentity>::ok(std::move(identity));
}

application::ClientResult<std::string> OpenSslCryptoProvider::encrypt_message(const domain::DeviceId& recipient_device,
                                                                              std::string_view plaintext) {
    if (recipient_device.empty()) {
        return application::ClientResult<std::string>::error(
            application::ClientError::crypto("Recipient device cannot be empty"));
    }
    return application::ClientResult<std::string>::ok("encrypted:" + std::string(plaintext));
}

application::ClientResult<std::string> OpenSslCryptoProvider::decrypt_message(const domain::DeviceId& sender_device,
                                                                              std::string_view ciphertext) {
    if (sender_device.empty()) {
        return application::ClientResult<std::string>::error(
            application::ClientError::crypto("Sender device cannot be empty"));
    }
    const std::string prefix = "encrypted:";
    if (ciphertext.rfind(prefix, 0) == 0) {
        return application::ClientResult<std::string>::ok(std::string(ciphertext.substr(prefix.size())));
    }
    return application::ClientResult<std::string>::ok(std::string(ciphertext));
}

application::ClientResult<bool> OpenSslCryptoProvider::verify_identity_fingerprint(const domain::DeviceId& device,
                                                                                   std::string_view fingerprint) {
    if (device.empty() || fingerprint.empty()) {
        return application::ClientResult<bool>::ok(false);
    }
    return application::ClientResult<bool>::ok(domain::CryptoIdentity::is_valid_fingerprint(fingerprint));
}

application::ClientResult<application::interfaces::DhKeyPair> OpenSslCryptoProvider::generate_dh_keypair() {
    auto key_res = generate_raw_evp_keypair(EVP_PKEY_X25519, domain::PrekeyPolicy::kX25519PublicKeySize);
    if (!key_res.is_ok()) {
        return application::ClientResult<application::interfaces::DhKeyPair>::error(key_res.error());
    }
    auto [pub, priv] = std::move(key_res).value();
    return application::ClientResult<application::interfaces::DhKeyPair>::ok(application::interfaces::DhKeyPair{
        .public_key = std::move(pub),
        .private_key = std::move(priv),
    });
}

application::ClientResult<securecloud::common::configuration::SecretString>
OpenSslCryptoProvider::diffie_hellman(const securecloud::common::configuration::SecretString& our_private_key,
                                      std::span<const uint8_t> peer_public_key) {
    if (our_private_key.size() != domain::PrekeyPolicy::kX25519PrivateKeySize) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Our private key must be exactly 32 bytes"));
    }
    if (peer_public_key.size() != domain::PrekeyPolicy::kX25519PublicKeySize) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Peer public key must be exactly 32 bytes"));
    }

    const auto& priv_bytes = our_private_key.expose_unredacted_secret();
    EVP_PKEY* priv_pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr, reinterpret_cast<const unsigned char*>(priv_bytes.data()), priv_bytes.size());
    if (!priv_pkey) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Failed to import X25519 private key: " + get_openssl_error_string()));
    }

    EVP_PKEY* peer_pkey =
        EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_public_key.data(), peer_public_key.size());
    if (!peer_pkey) {
        EVP_PKEY_free(priv_pkey);
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Failed to import peer X25519 public key: " + get_openssl_error_string()));
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(priv_pkey);
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Failed to create EVP_PKEY_CTX for derivation"));
    }

    if (EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, peer_pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(priv_pkey);
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Failed to init Diffie-Hellman derivation: " +
                                             get_openssl_error_string()));
    }

    std::size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0 || secret_len != domain::PrekeyPolicy::kSharedSecretSize) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(priv_pkey);
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Failed to determine shared secret length: " +
                                             get_openssl_error_string()));
    }

    std::vector<uint8_t> secret_buf(secret_len, 0);
    if (EVP_PKEY_derive(ctx, secret_buf.data(), &secret_len) <= 0 ||
        secret_len != domain::PrekeyPolicy::kSharedSecretSize) {
        OPENSSL_cleanse(secret_buf.data(), secret_buf.size());
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(priv_pkey);
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("EVP_PKEY_derive failed: " + get_openssl_error_string()));
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_pkey);
    EVP_PKEY_free(priv_pkey);

    std::string secret_str(reinterpret_cast<const char*>(secret_buf.data()), secret_buf.size());
    OPENSSL_cleanse(secret_buf.data(), secret_buf.size());

    return application::ClientResult<securecloud::common::configuration::SecretString>::ok(
        securecloud::common::configuration::SecretString(std::move(secret_str)));
}

application::ClientResult<securecloud::common::configuration::SecretString>
OpenSslCryptoProvider::hkdf_extract(std::span<const uint8_t> salt,
                                    const securecloud::common::configuration::SecretString& ikm) {
    if (ikm.empty()) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("HKDF IKM cannot be empty"));
    }
    const auto& ikm_bytes = ikm.expose_unredacted_secret();
    return derive_hkdf(EVP_KDF_HKDF_MODE_EXTRACT_ONLY, salt, ikm_bytes.data(), ikm_bytes.size(), {}, 32);
}

application::ClientResult<securecloud::common::configuration::SecretString>
OpenSslCryptoProvider::hkdf_expand(const securecloud::common::configuration::SecretString& prk,
                                   std::span<const uint8_t> info, std::size_t length) {
    if (prk.empty() || length == 0) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("HKDF Expand invalid parameters"));
    }
    const auto& prk_bytes = prk.expose_unredacted_secret();
    return derive_hkdf(EVP_KDF_HKDF_MODE_EXPAND_ONLY, {}, prk_bytes.data(), prk_bytes.size(), info, length);
}

application::ClientResult<securecloud::common::configuration::SecretString>
OpenSslCryptoProvider::hkdf_extract_and_expand(std::span<const uint8_t> salt,
                                               const securecloud::common::configuration::SecretString& ikm,
                                               std::span<const uint8_t> info, std::size_t length) {
    if (ikm.empty() || length == 0) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("HKDF Extract-and-Expand invalid parameters"));
    }
    const auto& ikm_bytes = ikm.expose_unredacted_secret();
    return derive_hkdf(EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND, salt, ikm_bytes.data(), ikm_bytes.size(), info, length);
}

application::ClientResult<application::interfaces::AeadCiphertext>
OpenSslCryptoProvider::encrypt_aes_gcm(const securecloud::common::configuration::SecretString& key,
                                       std::span<const uint8_t> iv, std::span<const uint8_t> plaintext,
                                       std::span<const uint8_t> associated_data) {
    if (key.size() != domain::PrekeyPolicy::kAes256KeySize) {
        return application::ClientResult<application::interfaces::AeadCiphertext>::error(
            application::ClientError::crypto("AES key must be 32 bytes"));
    }
    if (iv.size() != domain::PrekeyPolicy::kAeadGcmIvSize) {
        return application::ClientResult<application::interfaces::AeadCiphertext>::error(
            application::ClientError::crypto("AES GCM IV must be 12 bytes"));
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return application::ClientResult<application::interfaces::AeadCiphertext>::error(
            application::ClientError::crypto("Failed to create EVP_CIPHER_CTX"));
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return application::ClientResult<application::interfaces::AeadCiphertext>::error(
            application::ClientError::crypto("Failed to init AES-256-GCM cipher"));
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return application::ClientResult<application::interfaces::AeadCiphertext>::error(
            application::ClientError::crypto("Failed to set GCM IV length"));
    }

    const auto& key_bytes = key.expose_unredacted_secret();
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast<const unsigned char*>(key_bytes.data()),
                           iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return application::ClientResult<application::interfaces::AeadCiphertext>::error(
            application::ClientError::crypto("Failed to set GCM key and IV"));
    }

    int out_len = 0;
    if (!associated_data.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &out_len, associated_data.data(),
                              static_cast<int>(associated_data.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return application::ClientResult<application::interfaces::AeadCiphertext>::error(
                application::ClientError::crypto("Failed to process GCM AAD"));
        }
    }

    std::vector<uint8_t> ciphertext(plaintext.size());
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len, plaintext.data(), static_cast<int>(plaintext.size())) !=
            1) {
            EVP_CIPHER_CTX_free(ctx);
            return application::ClientResult<application::interfaces::AeadCiphertext>::error(
                application::ClientError::crypto("Failed to encrypt GCM plaintext"));
        }
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return application::ClientResult<application::interfaces::AeadCiphertext>::error(
            application::ClientError::crypto("Failed to finalize GCM encryption"));
    }

    std::vector<uint8_t> tag(domain::PrekeyPolicy::kAeadGcmTagSize);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return application::ClientResult<application::interfaces::AeadCiphertext>::error(
            application::ClientError::crypto("Failed to retrieve GCM auth tag"));
    }

    EVP_CIPHER_CTX_free(ctx);

    std::vector<uint8_t> iv_copy(iv.begin(), iv.end());
    return application::ClientResult<application::interfaces::AeadCiphertext>::ok(
        application::interfaces::AeadCiphertext{
            .ciphertext = std::move(ciphertext),
            .iv = std::move(iv_copy),
            .auth_tag = std::move(tag),
        });
}

application::ClientResult<securecloud::common::configuration::SecretString>
OpenSslCryptoProvider::decrypt_aes_gcm(const securecloud::common::configuration::SecretString& key,
                                       std::span<const uint8_t> iv, std::span<const uint8_t> ciphertext,
                                       std::span<const uint8_t> auth_tag, std::span<const uint8_t> associated_data) {
    if (key.size() != domain::PrekeyPolicy::kAes256KeySize) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("AES key must be 32 bytes"));
    }
    if (iv.size() != domain::PrekeyPolicy::kAeadGcmIvSize) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("AES GCM IV must be 12 bytes"));
    }
    if (auth_tag.size() != domain::PrekeyPolicy::kAeadGcmTagSize) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("AES GCM tag must be 16 bytes"));
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Failed to create EVP_CIPHER_CTX"));
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Failed to init AES-256-GCM cipher"));
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Failed to set GCM IV length"));
    }

    const auto& key_bytes = key.expose_unredacted_secret();
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast<const unsigned char*>(key_bytes.data()),
                           iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Failed to set GCM key and IV"));
    }

    int out_len = 0;
    if (!associated_data.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &out_len, associated_data.data(),
                              static_cast<int>(associated_data.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return application::ClientResult<securecloud::common::configuration::SecretString>::error(
                application::ClientError::crypto("Failed to process GCM AAD"));
        }
    }

    std::vector<uint8_t> plaintext(ciphertext.size());
    if (!ciphertext.empty()) {
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, ciphertext.data(),
                              static_cast<int>(ciphertext.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return application::ClientResult<securecloud::common::configuration::SecretString>::error(
                application::ClientError::crypto("Failed to decrypt GCM ciphertext"));
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(auth_tag.size()),
                            const_cast<uint8_t*>(auth_tag.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Failed to set GCM auth tag for verification"));
    }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len) <= 0) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        EVP_CIPHER_CTX_free(ctx);
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto(
                "AES-256-GCM authentication verification failed (tampered ciphertext, tag, or AAD)"));
    }

    EVP_CIPHER_CTX_free(ctx);

    std::string pt_str(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
    OPENSSL_cleanse(plaintext.data(), plaintext.size());

    return application::ClientResult<securecloud::common::configuration::SecretString>::ok(
        securecloud::common::configuration::SecretString(std::move(pt_str)));
}

application::ClientResult<std::string> OpenSslCryptoProvider::compute_safety_number(
    const domain::UserId& local_user_id, std::span<const uint8_t> local_identity_key,
    const domain::UserId& peer_user_id, std::span<const uint8_t> peer_identity_key) {
    if (local_user_id.empty() || peer_user_id.empty()) {
        return application::ClientResult<std::string>::error(
            application::ClientError::crypto("User IDs cannot be empty for safety number computation"));
    }
    if (local_identity_key.size() != domain::PrekeyPolicy::kEd25519PublicKeySize ||
        peer_identity_key.size() != domain::PrekeyPolicy::kEd25519PublicKeySize) {
        return application::ClientResult<std::string>::error(
            application::ClientError::crypto("Identity public keys must be 32 bytes"));
    }

    std::span<const uint8_t> first_key = local_identity_key;
    std::span<const uint8_t> second_key = peer_identity_key;
    if (std::lexicographical_compare(peer_identity_key.begin(), peer_identity_key.end(), local_identity_key.begin(),
                                     local_identity_key.end())) {
        std::swap(first_key, second_key);
    }

    std::string_view first_user = local_user_id.str();
    std::string_view second_user = peer_user_id.str();
    if (first_user > second_user) {
        std::swap(first_user, second_user);
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return application::ClientResult<std::string>::error(
            application::ClientError::crypto("Failed to create EVP_MD_CTX for safety number"));
    }

    std::vector<uint8_t> digest(64);
    unsigned int md_len = 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, first_key.data(), first_key.size()) != 1 ||
        EVP_DigestUpdate(ctx, second_key.data(), second_key.size()) != 1 ||
        EVP_DigestUpdate(ctx, first_user.data(), first_user.size()) != 1 ||
        EVP_DigestUpdate(ctx, second_user.data(), second_user.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, digest.data(), &md_len) != 1 || md_len != 64) {
        EVP_MD_CTX_free(ctx);
        return application::ClientResult<std::string>::error(
            application::ClientError::crypto("SHA-512 digest computation failed for safety number"));
    }
    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    for (std::size_t k = 0; k < 12; ++k) {
        uint64_t val = 0;
        for (std::size_t m = 0; m < 5; ++m) {
            val = (val << 8) | digest[k * 5 + m];
        }
        val %= 100000;
        if (k > 0) {
            oss << ' ';
        }
        oss << std::setw(5) << std::setfill('0') << val;
    }

    return application::ClientResult<std::string>::ok(oss.str());
}

} // namespace securecloud::client::infrastructure::adapters
