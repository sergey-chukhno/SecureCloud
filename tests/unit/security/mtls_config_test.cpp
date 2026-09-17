#include "securecloud/security/mtls_config.hpp"

#include <fstream>
#include <gtest/gtest.h>

namespace securecloud::common::security {
namespace {

class TestAuthPropertyIterator : public grpc::AuthPropertyIterator {
  public:
    TestAuthPropertyIterator() = default;
};

class TestAuthContext : public grpc::AuthContext {
  public:
    TestAuthContext(bool is_authenticated, std::vector<std::pair<std::string, std::string>> properties)
        : is_authenticated_(is_authenticated), properties_(std::move(properties)) {}

    [[nodiscard]] bool IsPeerAuthenticated() const override { return is_authenticated_; }

    [[nodiscard]] std::string GetPeerIdentityPropertyName() const override { return "x509_subject_alternative_name"; }

    [[nodiscard]] std::vector<grpc::string_ref> GetPeerIdentity() const override {
        std::vector<grpc::string_ref> result;
        for (const auto& [key, value] : properties_) {
            if (key == "x509_subject_alternative_name") {
                result.emplace_back(value.data(), value.size());
            }
        }
        return result;
    }

    [[nodiscard]] std::vector<grpc::string_ref> FindPropertyValues(const std::string& name) const override {
        std::vector<grpc::string_ref> result;
        for (const auto& [key, value] : properties_) {
            if (key == name) {
                result.emplace_back(value.data(), value.size());
            }
        }
        return result;
    }

    [[nodiscard]] grpc::AuthPropertyIterator begin() const override { return TestAuthPropertyIterator{}; }
    [[nodiscard]] grpc::AuthPropertyIterator end() const override { return TestAuthPropertyIterator{}; }
    void AddProperty(const std::string& /*name*/, const grpc::string_ref& /*value*/) override {}
    bool SetPeerIdentityPropertyName(const std::string& /*name*/) override { return false; }

  private:
    bool is_authenticated_;
    std::vector<std::pair<std::string, std::string>> properties_;
};

class MtlsConfigTest : public ::testing::Test {
  protected:
    void SetUp() override {
        temp_dir_ = std::filesystem::temp_directory_path() / "securecloud_mtls_unit_test";
        std::filesystem::create_directories(temp_dir_);

        valid_ca_path_ = temp_dir_ / "ca.crt";
        valid_cert_path_ = temp_dir_ / "service.crt";
        valid_key_path_ = temp_dir_ / "service.key";
        empty_file_path_ = temp_dir_ / "empty.txt";

        std::filesystem::path real_ca = "deploy/dev-pki/ca/ca.crt";
        std::filesystem::path real_cert = "deploy/dev-pki/services/auth/auth.crt";
        std::filesystem::path real_key = "deploy/dev-pki/services/auth/auth.key";

        if (std::filesystem::exists(real_ca) && std::filesystem::exists(real_cert) &&
            std::filesystem::exists(real_key)) {
            std::filesystem::copy_file(real_ca, valid_ca_path_, std::filesystem::copy_options::overwrite_existing);
            std::filesystem::copy_file(real_cert, valid_cert_path_, std::filesystem::copy_options::overwrite_existing);
            std::filesystem::copy_file(real_key, valid_key_path_, std::filesystem::copy_options::overwrite_existing);
        } else {
            write_file(valid_ca_path_, "-----BEGIN CERTIFICATE-----\nCA_TEST\n-----END CERTIFICATE-----\n");
            write_file(valid_cert_path_, "-----BEGIN CERTIFICATE-----\nCERT_TEST\n-----END CERTIFICATE-----\n");
            write_file(valid_key_path_, "-----BEGIN PRIVATE KEY-----\nKEY_TEST\n-----END PRIVATE KEY-----\n");
        }
        write_file(empty_file_path_, "");
    }

    void TearDown() override { std::filesystem::remove_all(temp_dir_); }

    static void write_file(const std::filesystem::path& path, std::string_view content) {
        std::ofstream stream(path, std::ios::out | std::ios::binary);
        stream << content;
    }

    std::filesystem::path temp_dir_;
    std::filesystem::path valid_ca_path_;
    std::filesystem::path valid_cert_path_;
    std::filesystem::path valid_key_path_;
    std::filesystem::path empty_file_path_;
};

TEST_F(MtlsConfigTest, MissingCaFileFailsClosed) {
    SecurityCredentialsConfig config{
        .ca_cert_path = temp_dir_ / "nonexistent_ca.crt",
        .service_cert_path = valid_cert_path_,
        .service_key_path = valid_key_path_,
    };

    EXPECT_THROW(MtlsCredentialLoader::load_credentials_or_throw(config), std::runtime_error);
}

TEST_F(MtlsConfigTest, MissingServiceKeyFailsClosed) {
    SecurityCredentialsConfig config{
        .ca_cert_path = valid_ca_path_,
        .service_cert_path = valid_cert_path_,
        .service_key_path = temp_dir_ / "nonexistent_key.key",
    };

    EXPECT_THROW(MtlsCredentialLoader::load_credentials_or_throw(config), std::runtime_error);
}

TEST_F(MtlsConfigTest, EmptyCredentialFileFailsClosed) {
    SecurityCredentialsConfig config{
        .ca_cert_path = valid_ca_path_,
        .service_cert_path = empty_file_path_,
        .service_key_path = valid_key_path_,
    };

    EXPECT_THROW(MtlsCredentialLoader::load_credentials_or_throw(config), std::runtime_error);
}

TEST_F(MtlsConfigTest, ValidCredentialLoadingSucceeds) {
    SecurityCredentialsConfig config{
        .ca_cert_path = valid_ca_path_,
        .service_cert_path = valid_cert_path_,
        .service_key_path = valid_key_path_,
    };

    LoadedCredentials loaded;
    EXPECT_NO_THROW(loaded = MtlsCredentialLoader::load_credentials_or_throw(config));
    EXPECT_FALSE(loaded.ca_cert_pem.empty());
    EXPECT_FALSE(loaded.service_cert_pem.empty());
    EXPECT_FALSE(loaded.service_key_pem.empty());
    EXPECT_NE(loaded.ca_cert_pem.find("-----BEGIN CERTIFICATE-----"), std::string::npos);
    EXPECT_NE(loaded.service_cert_pem.find("-----BEGIN CERTIFICATE-----"), std::string::npos);
    EXPECT_NE(loaded.service_key_pem.find("PRIVATE KEY-----"), std::string::npos);
}

TEST_F(MtlsConfigTest, CreateServerCredentialsSucceedsForValidConfig) {
    SecurityCredentialsConfig config{
        .ca_cert_path = valid_ca_path_,
        .service_cert_path = valid_cert_path_,
        .service_key_path = valid_key_path_,
    };

    auto server_creds = MtlsCredentialLoader::create_server_credentials(config);
    EXPECT_NE(server_creds, nullptr);
}

TEST_F(MtlsConfigTest, CreateClientCredentialsSucceedsForValidConfig) {
    SecurityCredentialsConfig config{
        .ca_cert_path = valid_ca_path_,
        .service_cert_path = valid_cert_path_,
        .service_key_path = valid_key_path_,
    };

    auto client_creds = MtlsCredentialLoader::create_client_credentials(config);
    EXPECT_NE(client_creds, nullptr);
}

TEST_F(MtlsConfigTest, ExtractPeerServiceIdentityFromSanDnsSucceeds) {
    TestAuthContext auth_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});

    auto identity = extract_peer_service_identity(auth_ctx);
    ASSERT_TRUE(identity.has_value());
    EXPECT_EQ(identity.value_or(""), "gateway");
}

TEST_F(MtlsConfigTest, ExtractPeerServiceIdentityRawSanSucceeds) {
    TestAuthContext auth_ctx(true, {{"x509_subject_alternative_name", "auth"}});

    auto identity = extract_peer_service_identity(auth_ctx);
    ASSERT_TRUE(identity.has_value());
    EXPECT_EQ(identity.value_or(""), "auth");
}

TEST_F(MtlsConfigTest, ExtractPeerServiceIdentityIgnoresCnFallback) {
    // Zero CN fallback policy: Only SAN DNS is extracted. If SAN is missing, returns nullopt.
    TestAuthContext auth_ctx(true, {{"x509_common_name", "messaging"}});

    auto identity = extract_peer_service_identity(auth_ctx);
    EXPECT_FALSE(identity.has_value());
}

TEST_F(MtlsConfigTest, ExtractPeerServiceIdentityUnauthenticatedReturnsNullopt) {
    TestAuthContext auth_ctx(false, {{"x509_subject_alternative_name", "DNS:files"}});

    auto identity = extract_peer_service_identity(auth_ctx);
    EXPECT_FALSE(identity.has_value());
}

TEST_F(MtlsConfigTest, VerifyPeerServiceIdentityMatchingAndMismatch) {
    TestAuthContext auth_ctx(true, {{"x509_subject_alternative_name", "DNS:audit"}});

    EXPECT_TRUE(verify_peer_service_identity(auth_ctx, "audit"));
    EXPECT_FALSE(verify_peer_service_identity(auth_ctx, "gateway"));
}

} // namespace
} // namespace securecloud::common::security
