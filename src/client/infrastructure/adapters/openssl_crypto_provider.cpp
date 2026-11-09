#include "infrastructure/adapters/openssl_crypto_provider.hpp"

#include "domain/prekey_policy.hpp"

#include <algorithm>
#include <array>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
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

} // namespace securecloud::client::infrastructure::adapters
