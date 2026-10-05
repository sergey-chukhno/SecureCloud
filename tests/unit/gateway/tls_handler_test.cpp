#include "gateway_config.hpp"
#include "tls/tls_handler.hpp"

#include <array>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <openssl/ssl.h>
#include <string>

namespace securecloud::gateway::tls {
namespace {

constexpr size_t k_proto_h2_len = 2;
constexpr size_t k_proto_http11_len = 8;
constexpr size_t k_dual_proto_len = 12;
constexpr size_t k_http11_proto_len = 9;
constexpr size_t k_spdy_proto_len = 5;

std::filesystem::path find_pki_dir() {
#ifdef SECURECLOUD_DEV_PKI_DIR
    std::filesystem::path p(SECURECLOUD_DEV_PKI_DIR);
    if (std::filesystem::exists(p / "ca" / "ca.crt")) {
        return p;
    }
#endif
    auto curr = std::filesystem::current_path();
    while (!curr.empty() && curr != curr.root_path()) {
        if (std::filesystem::exists(curr / "deploy" / "dev-pki" / "ca" / "ca.crt")) {
            return curr / "deploy" / "dev-pki";
        }
        curr = curr.parent_path();
    }
    return "deploy/dev-pki";
}

TEST(TlsHandlerTest, ValidDevPkiCertificatePairSucceeds) {
    auto pki_root = find_pki_dir();
    auto cert_path = pki_root / "services" / "gateway" / "gateway.crt";
    auto key_path = pki_root / "services" / "gateway" / "gateway.key";

    ASSERT_TRUE(std::filesystem::exists(cert_path)) << "Dev PKI cert missing at " << cert_path;
    ASSERT_TRUE(std::filesystem::exists(key_path)) << "Dev PKI key missing at " << key_path;

    std::string error;
    bool valid = TlsHandler::validate_certificate_pair(cert_path.string(), key_path.string(), error);

    EXPECT_TRUE(valid) << "Expected valid cert pair, got error: " << error;
    EXPECT_TRUE(error.empty());
}

TEST(TlsHandlerTest, MismatchedKeyFailsValidation) {
    auto pki_root = find_pki_dir();
    auto gw_cert = pki_root / "services" / "gateway" / "gateway.crt";
    auto auth_key = pki_root / "services" / "auth" / "auth.key";

    ASSERT_TRUE(std::filesystem::exists(gw_cert)) << "Gateway cert missing: " << gw_cert;
    ASSERT_TRUE(std::filesystem::exists(auth_key)) << "Auth key missing: " << auth_key;

    std::string error;
    bool valid = TlsHandler::validate_certificate_pair(gw_cert.string(), auth_key.string(), error);

    EXPECT_FALSE(valid);
    EXPECT_FALSE(error.empty());
    EXPECT_NE(error.find("match"), std::string::npos) << "Error should mention key mismatch: " << error;
}

TEST(TlsHandlerTest, CorruptedCertificateFailsValidation) {
    auto pki_root = find_pki_dir();
    auto valid_key = pki_root / "services" / "gateway" / "gateway.key";
    ASSERT_TRUE(std::filesystem::exists(valid_key));

    auto temp_dir = std::filesystem::temp_directory_path() / "securecloud_tls_corrupt_test";
    std::filesystem::create_directories(temp_dir);
    auto corrupt_cert = temp_dir / "corrupted.crt";

    {
        std::ofstream stream(corrupt_cert);
        stream << "-----BEGIN CERTIFICATE-----\nINVALID_DATA_GARBAGE\n-----END CERTIFICATE-----\n";
    }

    std::string error;
    bool valid = TlsHandler::validate_certificate_pair(corrupt_cert.string(), valid_key.string(), error);

    EXPECT_FALSE(valid);
    EXPECT_FALSE(error.empty());

    std::filesystem::remove_all(temp_dir);
}

TEST(TlsHandlerTest, NonExistentFileFailsValidation) {
    auto pki_root = find_pki_dir();
    auto valid_key = pki_root / "services" / "gateway" / "gateway.key";

    std::string error;
    bool valid = TlsHandler::validate_certificate_pair("/nonexistent/file/path.crt", valid_key.string(), error);

    EXPECT_FALSE(valid);
    EXPECT_NE(error.find("does not exist"), std::string::npos);
}

TEST(TlsHandlerTest, CreateServerContextEnforcesTls13) {
    auto pki_root = find_pki_dir();
    GatewayTlsConfig config;
    config.cert_path = (pki_root / "services" / "gateway" / "gateway.crt").string();
    config.key_path = (pki_root / "services" / "gateway" / "gateway.key").string();
    config.ca_chain_path = (pki_root / "ca" / "ca.crt").string();

    std::string error;
    auto ctx = TlsHandler::create_server_context(config, error);

    ASSERT_NE(ctx, nullptr) << "Failed to create SSL_CTX: " << error;
    EXPECT_TRUE(error.empty());

    // Verify minimum protocol version is strictly TLS 1.3
    EXPECT_EQ(SSL_CTX_get_min_proto_version(ctx.get()), TLS1_3_VERSION);
}

TEST(TlsHandlerTest, CreateServerContextFailsOnInvalidConfig) {
    GatewayTlsConfig config;
    config.cert_path = "/nonexistent/path/gateway.crt";
    config.key_path = "/nonexistent/path/gateway.key";

    std::string error;
    auto ctx = TlsHandler::create_server_context(config, error);

    EXPECT_EQ(ctx, nullptr);
    EXPECT_FALSE(error.empty());
}

TEST(TlsHandlerTest, AlpnSelectCallbackPrefersH2) {
    // Client proposes both h2 and http/1.1
    const std::array<unsigned char, k_dual_proto_len> client_protos = {
        2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1',
    };

    const unsigned char* selected = nullptr;
    unsigned char selected_len = 0;

    int res = TlsHandler::alpn_select_callback(nullptr, &selected, &selected_len, client_protos.data(),
                                               static_cast<unsigned int>(client_protos.size()), nullptr);

    EXPECT_EQ(res, SSL_TLSEXT_ERR_OK);
    ASSERT_EQ(selected_len, k_proto_h2_len);
    EXPECT_EQ(std::string_view(reinterpret_cast<const char*>(selected), selected_len), "h2");
}

TEST(TlsHandlerTest, AlpnSelectCallbackFallsBackToHttp11) {
    // Client proposes only http/1.1
    const std::array<unsigned char, k_http11_proto_len> client_protos = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};

    const unsigned char* selected = nullptr;
    unsigned char selected_len = 0;

    int res = TlsHandler::alpn_select_callback(nullptr, &selected, &selected_len, client_protos.data(),
                                               static_cast<unsigned int>(client_protos.size()), nullptr);

    EXPECT_EQ(res, SSL_TLSEXT_ERR_OK);
    ASSERT_EQ(selected_len, k_proto_http11_len);
    EXPECT_EQ(std::string_view(reinterpret_cast<const char*>(selected), selected_len), "http/1.1");
}

TEST(TlsHandlerTest, AlpnSelectCallbackRejectsUnsupportedProtocols) {
    // Client proposes unsupported protocol "spdy"
    const std::array<unsigned char, k_spdy_proto_len> client_protos = {4, 's', 'p', 'd', 'y'};

    const unsigned char* selected = nullptr;
    unsigned char selected_len = 0;

    int res = TlsHandler::alpn_select_callback(nullptr, &selected, &selected_len, client_protos.data(),
                                               static_cast<unsigned int>(client_protos.size()), nullptr);

    EXPECT_EQ(res, SSL_TLSEXT_ERR_NOACK);
}

} // namespace
} // namespace securecloud::gateway::tls
