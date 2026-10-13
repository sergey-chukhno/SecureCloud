#include "auth/crypto/token_crypto.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/token_claims.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/service/auth_service_impl.hpp"
#include "auth/service/token_manager.hpp"
#include "http/auth/local_token_verifier.hpp"
#include "securecloud/auth/v1/auth.grpc.pb.h"

#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::auth::service::test {
namespace {

using ::testing::_;

class MockTokenManager : public ITokenManager {
  public:
    explicit MockTokenManager(std::shared_ptr<crypto::ITokenSigner> signer = nullptr) : signer_(std::move(signer)) {}

    MOCK_METHOD(domain::TokenPair, issue_initial_tokens,
                (const domain::SessionEntity&, const std::vector<std::string>&), (override));

    domain::TokenRefreshResult refresh_tokens(std::string_view refresh_token_raw,
                                              const domain::Uuid& presented_device_id,
                                              std::string_view ip_address) override {
        return refresh_tokens_impl(std::string(refresh_token_raw), presented_device_id, std::string(ip_address));
    }
    MOCK_METHOD(domain::TokenRefreshResult, refresh_tokens_impl,
                (const std::string&, const domain::Uuid&, const std::string&));

    [[nodiscard]] std::shared_ptr<crypto::ITokenSigner> signer() const noexcept override { return signer_; }

    void set_signer(std::shared_ptr<crypto::ITokenSigner> signer) noexcept { signer_ = std::move(signer); }

  private:
    std::shared_ptr<crypto::ITokenSigner> signer_;
};

// ============================================================================
// 1. Success & Cryptographic Soundness Tests
// ============================================================================

TEST(AuthServicePublicKeyTest, GetPublicSigningKeySuccess_ExportsExpectedMaterial) {
    auto signer = std::make_shared<crypto::Ed25519TokenSigner>("auth-key-2026");
    auto mock_tm = std::make_shared<MockTokenManager>(signer);

    AuthServiceImpl service(nullptr, nullptr, nullptr, mock_tm, nullptr, nullptr, nullptr, nullptr);

    grpc::ServerContext context;
    securecloud::auth::v1::GetPublicSigningKeyRequest req;
    securecloud::auth::v1::GetPublicSigningKeyResponse resp;

    auto status = service.GetPublicSigningKey(&context, &req, &resp);

    EXPECT_TRUE(status.ok());
    EXPECT_EQ(resp.key_id(), "auth-key-2026");
    EXPECT_EQ(resp.algorithm(), "Ed25519");
    EXPECT_EQ(resp.public_key_raw().size(), 32u);
    EXPECT_NE(resp.public_key_pem().find("BEGIN PUBLIC KEY"), std::string::npos);
    EXPECT_NE(resp.public_key_pem().find("END PUBLIC KEY"), std::string::npos);

    // Invariant ADR-008: Zero Private Key Ingress / Wire Exposure
    EXPECT_EQ(resp.public_key_pem().find("PRIVATE KEY"), std::string::npos);
}

TEST(AuthServicePublicKeyTest, GetPublicSigningKeyMatchesSignerKeyMaterial) {
    auto signer = std::make_shared<crypto::Ed25519TokenSigner>("test-key-id");
    auto mock_tm = std::make_shared<MockTokenManager>(signer);

    AuthServiceImpl service(nullptr, nullptr, nullptr, mock_tm, nullptr, nullptr, nullptr, nullptr);

    grpc::ServerContext context;
    securecloud::auth::v1::GetPublicSigningKeyRequest req;
    securecloud::auth::v1::GetPublicSigningKeyResponse resp;

    auto status = service.GetPublicSigningKey(&context, &req, &resp);
    ASSERT_TRUE(status.ok());

    auto expected_raw = signer->get_public_key_raw();
    std::string expected_raw_str(reinterpret_cast<const char*>(expected_raw.data()), expected_raw.size());
    EXPECT_EQ(resp.public_key_raw(), expected_raw_str);
    EXPECT_EQ(resp.public_key_pem(), signer->get_public_key_pem());

    // Verify raw key builds a functioning Ed25519TokenVerifier
    std::vector<uint8_t> raw_bytes(resp.public_key_raw().begin(), resp.public_key_raw().end());
    auto verifier_from_raw = crypto::Ed25519TokenVerifier::from_public_key_raw(raw_bytes, resp.key_id());
    ASSERT_NE(verifier_from_raw, nullptr);

    // Verify PEM builds a functioning Ed25519TokenVerifier
    auto verifier_from_pem = crypto::Ed25519TokenVerifier::from_public_key_pem(resp.public_key_pem(), resp.key_id());
    ASSERT_NE(verifier_from_pem, nullptr);

    // Cryptographic signature test across both verifiers
    std::string test_payload = "securecloud-perimeter-test-message";
    std::string sig = signer->sign(test_payload);
    EXPECT_TRUE(verifier_from_raw->verify(test_payload, sig));
    EXPECT_TRUE(verifier_from_pem->verify(test_payload, sig));
}

TEST(AuthServicePublicKeyTest, LocalTokenVerifierOfflineInteroperability) {
    auto signer = std::make_shared<crypto::Ed25519TokenSigner>("sc-auth-v1");
    auto mock_tm = std::make_shared<MockTokenManager>(signer);

    AuthServiceImpl service(nullptr, nullptr, nullptr, mock_tm, nullptr, nullptr, nullptr, nullptr);

    grpc::ServerContext context;
    securecloud::auth::v1::GetPublicSigningKeyRequest req;
    securecloud::auth::v1::GetPublicSigningKeyResponse resp;

    auto status = service.GetPublicSigningKey(&context, &req, &resp);
    ASSERT_TRUE(status.ok());

    // Gateway constructs LocalTokenVerifier strictly from AuthService public key response
    auto local_verifier =
        securecloud::gateway::http::LocalTokenVerifier::from_public_key_pem(resp.public_key_pem(), resp.key_id());
    ASSERT_NE(local_verifier, nullptr);

    // Generate valid token claims signed by AuthService
    domain::AccessTokenClaims claims;
    claims.issuer = "https://auth.securecloud.io";
    claims.audience = "https://gateway.securecloud.io";
    claims.user_id = domain::Uuid::generate_v7();
    claims.device_id = domain::Uuid::generate_v7();
    claims.session_id = domain::Uuid::generate_v7();
    claims.issued_at = std::chrono::system_clock::now();
    claims.expires_at = claims.issued_at + std::chrono::minutes(15);
    claims.jti = domain::Uuid::generate_v7();
    claims.scopes = {"access", "files:read"};
    claims.token_version = 1;
    claims.authentication_level = domain::AuthenticationLevel::PrimaryOnly;

    std::string token = domain::TokenEnvelopeSerializer::serialize(claims, *signer);

    // Validate offline at Gateway perimeter (zero network calls)
    auto auth_result = local_verifier->validate(token, claims.session_id.to_string());
    ASSERT_TRUE(auth_result.has_value());
    EXPECT_EQ(auth_result.value().user_id(), claims.user_id.to_string());
    EXPECT_EQ(auth_result.value().device_id(), claims.device_id.to_string());
    EXPECT_EQ(auth_result.value().session_id(), claims.session_id.to_string());
}

// ============================================================================
// 2. Precondition & Error Handling Tests
// ============================================================================

TEST(AuthServicePublicKeyTest, FailsWhenTokenManagerNotConfigured) {
    // Service initialized with nullptr token_manager
    AuthServiceImpl service(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    grpc::ServerContext context;
    securecloud::auth::v1::GetPublicSigningKeyRequest req;
    securecloud::auth::v1::GetPublicSigningKeyResponse resp;

    auto status = service.GetPublicSigningKey(&context, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::FAILED_PRECONDITION);
    EXPECT_NE(status.error_message().find("Token service not configured"), std::string::npos);
}

TEST(AuthServicePublicKeyTest, FailsWhenSignerNull) {
    // TokenManager present, but signer returns nullptr
    auto mock_tm = std::make_shared<MockTokenManager>(nullptr);
    AuthServiceImpl service(nullptr, nullptr, nullptr, mock_tm, nullptr, nullptr, nullptr, nullptr);

    grpc::ServerContext context;
    securecloud::auth::v1::GetPublicSigningKeyRequest req;
    securecloud::auth::v1::GetPublicSigningKeyResponse resp;

    auto status = service.GetPublicSigningKey(&context, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::FAILED_PRECONDITION);
    EXPECT_NE(status.error_message().find("Token signer not configured"), std::string::npos);
}

TEST(AuthServicePublicKeyTest, RejectsNullArguments) {
    auto signer = std::make_shared<crypto::Ed25519TokenSigner>("auth-key");
    auto mock_tm = std::make_shared<MockTokenManager>(signer);
    AuthServiceImpl service(nullptr, nullptr, nullptr, mock_tm, nullptr, nullptr, nullptr, nullptr);

    grpc::ServerContext context;
    securecloud::auth::v1::GetPublicSigningKeyRequest req;
    securecloud::auth::v1::GetPublicSigningKeyResponse resp;

    auto status_null_req = service.GetPublicSigningKey(&context, nullptr, &resp);
    EXPECT_EQ(status_null_req.error_code(), grpc::StatusCode::INVALID_ARGUMENT);

    auto status_null_resp = service.GetPublicSigningKey(&context, &req, nullptr);
    EXPECT_EQ(status_null_resp.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

} // namespace
} // namespace securecloud::auth::service::test
