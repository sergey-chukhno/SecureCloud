#include "security/grpc_producer_identity_validator.hpp"

#include <gtest/gtest.h>

namespace grpc::testing {

class ServerContextTestSpouse {
  public:
    explicit ServerContextTestSpouse(::grpc::ServerContext* ctx) : ctx_(ctx) {}

    void set_auth_context(std::shared_ptr<const ::grpc::AuthContext> auth_context) {
        ctx_->auth_context_ = std::move(auth_context);
    }

  private:
    ::grpc::ServerContext* ctx_;
};

} // namespace grpc::testing

namespace securecloud::audit::security::testing {

class TestAuthPropertyIterator : public ::grpc::AuthPropertyIterator {
  public:
    TestAuthPropertyIterator() = default;
};

class TestAuthContext : public ::grpc::AuthContext {
  public:
    explicit TestAuthContext(bool is_authenticated, std::vector<std::pair<std::string, std::string>> properties = {})
        : is_authenticated_(is_authenticated), properties_(std::move(properties)) {}

    [[nodiscard]] bool IsPeerAuthenticated() const override { return is_authenticated_; }

    [[nodiscard]] std::string GetPeerIdentityPropertyName() const override { return "x509_subject_alternative_name"; }

    [[nodiscard]] std::vector<::grpc::string_ref> GetPeerIdentity() const override {
        std::vector<::grpc::string_ref> result;
        for (const auto& [key, value] : properties_) {
            if (key == "x509_subject_alternative_name") {
                result.emplace_back(value.data(), value.size());
            }
        }
        return result;
    }

    [[nodiscard]] std::vector<::grpc::string_ref> FindPropertyValues(const std::string& name) const override {
        std::vector<::grpc::string_ref> result;
        for (const auto& [key, value] : properties_) {
            if (key == name) {
                result.emplace_back(value.data(), value.size());
            }
        }
        return result;
    }

    [[nodiscard]] ::grpc::AuthPropertyIterator begin() const override { return TestAuthPropertyIterator{}; }
    [[nodiscard]] ::grpc::AuthPropertyIterator end() const override { return TestAuthPropertyIterator{}; }

    void AddProperty(const std::string& key, const ::grpc::string_ref& value) override {
        properties_.emplace_back(key, std::string(value.data(), value.size()));
    }

    bool SetPeerIdentityPropertyName(const std::string& /*name*/) override { return true; }

  private:
    bool is_authenticated_{false};
    std::vector<std::pair<std::string, std::string>> properties_;
};

class GrpcProducerIdentityValidatorTest : public ::testing::Test {
  protected:
    void SetUp() override { GrpcProducerIdentityValidator::set_bypass_peer_verification_for_testing(false); }

    void TearDown() override { GrpcProducerIdentityValidator::set_bypass_peer_verification_for_testing(false); }
};

TEST_F(GrpcProducerIdentityValidatorTest, RejectUnauthenticatedContext) {
    grpc::ServerContext unauthenticated_ctx{};
    auto status =
        GrpcProducerIdentityValidator::validate_peer_context(unauthenticated_ctx, domain::ProducerService::Auth);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
    EXPECT_NE(status.error_message().find("Authentication required"), std::string::npos);
}

TEST_F(GrpcProducerIdentityValidatorTest, RejectInvalidProducerString) {
    grpc::ServerContext ctx{};
    auto status = GrpcProducerIdentityValidator::validate_peer_context(ctx, "invalid_producer_service");

    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST_F(GrpcProducerIdentityValidatorTest, AuthorizeValidMtlsPeer) {
    grpc::ServerContext ctx{};
    grpc::testing::ServerContextTestSpouse spouse(&ctx);
    auto auth_ctx = std::make_shared<TestAuthContext>(
        true, std::vector<std::pair<std::string, std::string>>{
                  {"x509_subject_alternative_name", "DNS:auth.securecloud.internal"}});
    spouse.set_auth_context(auth_ctx);

    auto status = GrpcProducerIdentityValidator::validate_peer_context(ctx, domain::ProducerService::Auth);
    EXPECT_TRUE(status.ok());
}

TEST_F(GrpcProducerIdentityValidatorTest, RejectMismatchedMtlsPeer) {
    grpc::ServerContext ctx{};
    grpc::testing::ServerContextTestSpouse spouse(&ctx);
    auto auth_ctx = std::make_shared<TestAuthContext>(
        true, std::vector<std::pair<std::string, std::string>>{
                  {"x509_subject_alternative_name", "DNS:gateway.securecloud.internal"}});
    spouse.set_auth_context(auth_ctx);

    auto status = GrpcProducerIdentityValidator::validate_peer_context(ctx, domain::ProducerService::Auth);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

TEST_F(GrpcProducerIdentityValidatorTest, ExtractPeerIdentitySanAndCn) {
    grpc::ServerContext ctx{};
    grpc::testing::ServerContextTestSpouse spouse(&ctx);
    auto auth_ctx = std::make_shared<TestAuthContext>(
        true, std::vector<std::pair<std::string, std::string>>{
                  {"x509_common_name", "messaging.securecloud.internal"},
                  {"x509_subject_alternative_name", "DNS:messaging.securecloud.internal"}});
    spouse.set_auth_context(auth_ctx);

    auto identity = GrpcProducerIdentityValidator::extract_peer_identity(ctx);
    EXPECT_TRUE(identity.is_authenticated);
    EXPECT_EQ(identity.common_name, "messaging.securecloud.internal");
    ASSERT_EQ(identity.san_dns_names.size(), 1u);
    EXPECT_EQ(identity.san_dns_names[0], "messaging.securecloud.internal");
}

TEST_F(GrpcProducerIdentityValidatorTest, BypassForTestingWorks) {
    GrpcProducerIdentityValidator::set_bypass_peer_verification_for_testing(true);
    grpc::ServerContext unauthenticated_ctx{};
    auto status =
        GrpcProducerIdentityValidator::validate_peer_context(unauthenticated_ctx, domain::ProducerService::Auth);
    EXPECT_TRUE(status.ok());
}

} // namespace securecloud::audit::security::testing
