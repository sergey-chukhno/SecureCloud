#pragma once

#include "gateway_config.hpp"

#include <memory>
#include <string>

// Forward declarations for OpenSSL C structures
typedef struct ssl_ctx_st SSL_CTX;
typedef struct x509_st X509;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct bio_st BIO;
typedef struct ssl_st SSL;

namespace securecloud::gateway::tls {

struct SslCtxDeleter {
    void operator()(SSL_CTX* ctx) const noexcept;
};

struct X509Deleter {
    void operator()(X509* cert) const noexcept;
};

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* pkey) const noexcept;
};

struct BioDeleter {
    void operator()(BIO* bio) const noexcept;
};

using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;
using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using BioPtr = std::unique_ptr<BIO, BioDeleter>;

/// Cryptographic engine and TLS 1.3 gatekeeper for Gateway HTTPS listener (GW-002-TC-02).
class TlsHandler {
  public:
    /// Mathematically verifies that cert_path and key_path match and are valid x509 PEM files.
    /// Checks expiry dates (notBefore and notAfter) against the current clock.
    [[nodiscard]] static bool validate_certificate_pair(const std::string& cert_path, const std::string& key_path,
                                                        std::string& out_error);

    /// Initializes and hardens an OpenSSL server context enforcing TLS 1.3 protocol clamping,
    /// modern AEAD cipher suites, ALPN negotiation, and fail-closed certificate binding.
    [[nodiscard]] static SslCtxPtr create_server_context(const GatewayTlsConfig& config, std::string& out_error);

    /// Configures an existing OpenSSL server context enforcing TLS 1.3 protocol clamping,
    /// modern AEAD cipher suites, disabled session tickets/compression, and ALPN negotiation.
    [[nodiscard]] static bool configure_server_context(SSL_CTX* ctx, const GatewayTlsConfig& config,
                                                       std::string& out_error);

    /// OpenSSL ALPN callback negotiating HTTP/2 ("h2") and HTTP/1.1 ("http/1.1").
    static int alpn_select_callback(SSL* ssl, const unsigned char** out, unsigned char* outlen, const unsigned char* in,
                                    unsigned int inlen, void* arg);
};

} // namespace securecloud::gateway::tls
