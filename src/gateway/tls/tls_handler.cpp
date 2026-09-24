#include "tls/tls_handler.hpp"

#include <array>
#include <filesystem>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

namespace securecloud::gateway::tls {

void SslCtxDeleter::operator()(SSL_CTX* ctx) const noexcept {
    if (ctx != nullptr) {
        SSL_CTX_free(ctx);
    }
}

void X509Deleter::operator()(X509* cert) const noexcept {
    if (cert != nullptr) {
        X509_free(cert);
    }
}

void EvpPkeyDeleter::operator()(EVP_PKEY* pkey) const noexcept {
    if (pkey != nullptr) {
        EVP_PKEY_free(pkey);
    }
}

void BioDeleter::operator()(BIO* bio) const noexcept {
    if (bio != nullptr) {
        BIO_free(bio);
    }
}

namespace {

constexpr size_t k_openssl_err_buffer_size = 256;
constexpr size_t k_server_protos_len = 12;

std::string drain_openssl_errors() {
    std::string err_str;
    unsigned long err = 0;
    std::array<char, k_openssl_err_buffer_size> buf{};
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, buf.data(), buf.size());
        if (!err_str.empty()) {
            err_str += "; ";
        }
        err_str += buf.data();
    }
    return err_str.empty() ? "unknown OpenSSL error" : err_str;
}

X509Ptr load_x509_cert(const std::string& path, std::string& out_error) {
    if (!std::filesystem::exists(path)) {
        out_error = "Certificate file does not exist: '" + path + "'";
        return nullptr;
    }

    BioPtr bio(BIO_new_file(path.c_str(), "rb"));
    if (!bio) {
        out_error = "Failed to open certificate file '" + path + "': " + drain_openssl_errors();
        return nullptr;
    }

    X509* cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    if (cert == nullptr) {
        out_error = "Failed to parse X.509 certificate PEM in '" + path + "': " + drain_openssl_errors();
        return nullptr;
    }

    return X509Ptr(cert);
}

EvpPkeyPtr load_private_key(const std::string& path, std::string& out_error) {
    if (!std::filesystem::exists(path)) {
        out_error = "Private key file does not exist: '" + path + "'";
        return nullptr;
    }

    BioPtr bio(BIO_new_file(path.c_str(), "rb"));
    if (!bio) {
        out_error = "Failed to open private key file '" + path + "': " + drain_openssl_errors();
        return nullptr;
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    if (pkey == nullptr) {
        out_error = "Failed to parse private key PEM in '" + path + "': " + drain_openssl_errors();
        return nullptr;
    }

    return EvpPkeyPtr(pkey);
}

bool check_certificate_expiry(X509* cert, std::string& out_error) {
    const ASN1_TIME* not_after = X509_get0_notAfter(cert);
    if (not_after != nullptr && X509_cmp_current_time(not_after) <= 0) {
        out_error = "Certificate has expired";
        return false;
    }

    const ASN1_TIME* not_before = X509_get0_notBefore(cert);
    if (not_before != nullptr && X509_cmp_current_time(not_before) >= 0) {
        out_error = "Certificate is not yet valid";
        return false;
    }

    return true;
}

bool configure_context_security(SSL_CTX* ctx, const GatewayTlsConfig& config, std::string& out_error) {
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1) {
        out_error = "Failed to set minimum protocol version to TLS 1.3: " + drain_openssl_errors();
        return false;
    }
    SSL_CTX_set_max_proto_version(ctx, 0);

    if (SSL_CTX_set_ciphersuites(ctx, config.cipher_suites.c_str()) != 1) {
        out_error = "Failed to set TLS 1.3 cipher suites '" + config.cipher_suites + "': " + drain_openssl_errors();
        return false;
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_alpn_select_cb(ctx, TlsHandler::alpn_select_callback, nullptr);

    return true;
}

bool load_context_credentials(SSL_CTX* ctx, const GatewayTlsConfig& config, std::string& out_error) {
    if (SSL_CTX_use_certificate_chain_file(ctx, config.cert_path.c_str()) != 1) {
        out_error = "Failed to load certificate chain from '" + config.cert_path + "': " + drain_openssl_errors();
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, config.key_path.c_str(), SSL_FILETYPE_PEM) != 1) {
        out_error = "Failed to load private key from '" + config.key_path + "': " + drain_openssl_errors();
        return false;
    }

    if (SSL_CTX_check_private_key(ctx) != 1) {
        out_error = "Private key does not match certificate: " + drain_openssl_errors();
        return false;
    }

    if (!config.ca_chain_path.empty() && std::filesystem::exists(config.ca_chain_path) &&
        SSL_CTX_load_verify_locations(ctx, config.ca_chain_path.c_str(), nullptr) != 1) {
        out_error = "Failed to load CA chain from '" + config.ca_chain_path + "': " + drain_openssl_errors();
        return false;
    }

    return true;
}

} // namespace

bool TlsHandler::validate_certificate_pair(const std::string& cert_path, const std::string& key_path,
                                           std::string& out_error) {
    auto cert = load_x509_cert(cert_path, out_error);
    if (!cert) {
        return false;
    }

    auto pkey = load_private_key(key_path, out_error);
    if (!pkey) {
        return false;
    }

    if (X509_check_private_key(cert.get(), pkey.get()) != 1) {
        out_error = "Certificate and private key do not match mathematically: " + drain_openssl_errors();
        return false;
    }

    return check_certificate_expiry(cert.get(), out_error);
}

SslCtxPtr TlsHandler::create_server_context(const GatewayTlsConfig& config, std::string& out_error) {
    if (!validate_certificate_pair(config.cert_path, config.key_path, out_error)) {
        return nullptr;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == nullptr) {
        out_error = "Failed to create OpenSSL SSL_CTX: " + drain_openssl_errors();
        return nullptr;
    }
    SslCtxPtr ctx_ptr(ctx);

    if (!configure_context_security(ctx_ptr.get(), config, out_error)) {
        return nullptr;
    }

    if (!load_context_credentials(ctx_ptr.get(), config, out_error)) {
        return nullptr;
    }

    return ctx_ptr;
}

int TlsHandler::alpn_select_callback(SSL* /*ssl*/, const unsigned char** out, unsigned char* outlen,
                                     const unsigned char* in, unsigned int inlen, void* /*arg*/) {
    static const std::array<unsigned char, k_server_protos_len> k_server_protos = {
        2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1',
    };

    int status = SSL_select_next_proto(const_cast<unsigned char**>(out), outlen, k_server_protos.data(),
                                       static_cast<unsigned int>(k_server_protos.size()), in, inlen);
    if (status != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}

} // namespace securecloud::gateway::tls
