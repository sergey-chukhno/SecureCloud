#include "service/messaging_caller_context.hpp"

#include <deque>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace grpc::testing {

class ServerContextTestSpouse {
  public:
    explicit ServerContextTestSpouse(::grpc::ServerContext* ctx) : ctx_(ctx) {}

    void add_client_metadata(const std::string& key, const std::string& val) {
        stored_strings_.push_back(key);
        stored_strings_.push_back(val);
        const auto& k = stored_strings_[stored_strings_.size() - 2];
        const auto& v = stored_strings_.back();
        ctx_->client_metadata_.map()->insert(
            std::make_pair(::grpc::string_ref(k.data(), k.size()), ::grpc::string_ref(v.data(), v.size())));
    }

    void set_auth_context(std::shared_ptr<const ::grpc::AuthContext> auth_context) {
        ctx_->auth_context_ = std::move(auth_context);
    }

  private:
    ::grpc::ServerContext* ctx_;
    std::deque<std::string> stored_strings_;
};

} // namespace grpc::testing

namespace securecloud::messaging::service {
namespace {

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

// ============================================================================
// Idempotency Token Format Validation Tests
// ============================================================================

TEST(MessagingCallerContextTest, ValidIdempotencyTokensPass) {
    // 16 characters (minimum length)
    EXPECT_TRUE(is_valid_idempotency_token("1234567890abcdef"));
    EXPECT_TRUE(is_valid_idempotency_token("a-b_c-d_1-2_3-4_"));

    // 32 characters
    EXPECT_TRUE(is_valid_idempotency_token("0191ec4d91b47b4db6a98e41e3d36000"));

    // 64 characters (maximum length)
    constexpr size_t k_max_valid_token_len = 64;
    std::string max_token(k_max_valid_token_len, 'x');
    EXPECT_TRUE(is_valid_idempotency_token(max_token));
    EXPECT_TRUE(is_valid_idempotency_token("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"));
}

TEST(MessagingCallerContextTest, InvalidIdempotencyTokenLengthRejected) {
    EXPECT_FALSE(is_valid_idempotency_token(""));
    EXPECT_FALSE(is_valid_idempotency_token("1234567890abcde")); // 15 characters (too short)
    constexpr size_t k_too_long_token_len = 65;
    std::string too_long(k_too_long_token_len, 'y');
    EXPECT_FALSE(is_valid_idempotency_token(too_long)); // 65 characters (too long)
}

TEST(MessagingCallerContextTest, InvalidIdempotencyTokenCharactersRejected) {
    EXPECT_FALSE(is_valid_idempotency_token("1234567890abcde ")); // space
    EXPECT_FALSE(is_valid_idempotency_token("1234567890abcde.")); // period
    EXPECT_FALSE(is_valid_idempotency_token("1234567890abcde/")); // slash
    EXPECT_FALSE(is_valid_idempotency_token("1234567890abcde:")); // colon
    EXPECT_FALSE(is_valid_idempotency_token("1234567890abcde!")); // exclamation
}

// ============================================================================
// Extract Messaging Caller Context Tests
// ============================================================================

TEST(MessagingCallerContextTest, ExtractMessagingCallerContextNullReturnsDefault) {
    MessagingCallerContext ctx = extract_messaging_caller_context(nullptr);
    EXPECT_TRUE(ctx.user_id().empty());
    EXPECT_TRUE(ctx.device_id().empty());
    EXPECT_TRUE(ctx.correlation_id().empty());
    EXPECT_TRUE(ctx.idempotency_token.empty());
    EXPECT_EQ(ctx.peer_identity(), "anonymous");
}

TEST(MessagingCallerContextTest, ExtractMessagingCallerContextPopulatesAllFields) {
    ::grpc::ServerContext server_ctx;
    ::grpc::testing::ServerContextTestSpouse spouse(&server_ctx);

    spouse.add_client_metadata("x-correlation-id", "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    spouse.add_client_metadata("x-user-id", "550e8400-e29b-41d4-a716-446655440000");
    spouse.add_client_metadata("x-device-id", "a0b1c2d3-e4f5-6789-abcd-ef0123456789");
    spouse.add_client_metadata("x-idempotency-token", "client-token-1234567890");
    spouse.set_auth_context(std::make_shared<TestAuthContext>(
        true, std::vector<std::pair<std::string, std::string>>{{"x509_subject_alternative_name", "DNS:gateway"}}));

    MessagingCallerContext ctx = extract_messaging_caller_context(&server_ctx);
    EXPECT_EQ(ctx.correlation_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    EXPECT_EQ(ctx.user_id(), "550e8400-e29b-41d4-a716-446655440000");
    EXPECT_EQ(ctx.device_id(), "a0b1c2d3-e4f5-6789-abcd-ef0123456789");
    EXPECT_EQ(ctx.idempotency_token, "client-token-1234567890");
    EXPECT_EQ(ctx.peer_identity(), "gateway");
}

// ============================================================================
// Context Requirements Validation Tests
// ============================================================================

TEST(MessagingCallerContextTest, ValidateRequirementsEmptyRequirementPasses) {
    MessagingCallerContext empty_ctx;
    std::string error;
    auto status = validate_messaging_caller_context(empty_ctx, kRequireNone, error);
    EXPECT_TRUE(status.ok());
    EXPECT_TRUE(error.empty());
}

TEST(MessagingCallerContextTest, ValidatePeerRequirement) {
    MessagingCallerContext ctx;
    ctx.base.peer_identity = "anonymous";
    std::string error;
    auto status = validate_messaging_caller_context(ctx, kRequireAuthorizedPeer, error);
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::PERMISSION_DENIED);
    EXPECT_FALSE(error.empty());

    ctx.base.peer_identity = "gateway";
    status = validate_messaging_caller_context(ctx, kRequireAuthorizedPeer, error);
    EXPECT_TRUE(status.ok());
    EXPECT_TRUE(error.empty());
}

TEST(MessagingCallerContextTest, ValidateCorrelationIdRequirement) {
    MessagingCallerContext ctx;
    std::string error;
    auto status = validate_messaging_caller_context(ctx, kRequireCorrelationId, error);
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::INVALID_ARGUMENT);

    ctx.base.correlation_id = "invalid-uuid";
    status = validate_messaging_caller_context(ctx, kRequireCorrelationId, error);
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::INVALID_ARGUMENT);

    ctx.base.correlation_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000";
    status = validate_messaging_caller_context(ctx, kRequireCorrelationId, error);
    EXPECT_TRUE(status.ok());
}

TEST(MessagingCallerContextTest, ValidateUserIdRequirement) {
    MessagingCallerContext ctx;
    std::string error;
    auto status = validate_messaging_caller_context(ctx, kRequireUserId, error);
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::UNAUTHENTICATED);

    ctx.base.user_id = "not-a-valid-uuid";
    status = validate_messaging_caller_context(ctx, kRequireUserId, error);
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::UNAUTHENTICATED);

    ctx.base.user_id = "550e8400-e29b-41d4-a716-446655440000";
    status = validate_messaging_caller_context(ctx, kRequireUserId, error);
    EXPECT_TRUE(status.ok());
}

TEST(MessagingCallerContextTest, ValidateDeviceIdRequirement) {
    MessagingCallerContext ctx;
    std::string error;
    auto status = validate_messaging_caller_context(ctx, kRequireDeviceId, error);
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::INVALID_ARGUMENT);

    ctx.base.device_id = "not-a-valid-uuid";
    status = validate_messaging_caller_context(ctx, kRequireDeviceId, error);
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::INVALID_ARGUMENT);

    ctx.base.device_id = "a0b1c2d3-e4f5-6789-abcd-ef0123456789";
    status = validate_messaging_caller_context(ctx, kRequireDeviceId, error);
    EXPECT_TRUE(status.ok());
}

TEST(MessagingCallerContextTest, ValidateIdempotencyRequirement) {
    MessagingCallerContext ctx;
    std::string error;
    auto status = validate_messaging_caller_context(ctx, kRequireIdempotency, error);
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::INVALID_ARGUMENT);

    ctx.idempotency_token = "short"; // < 16 chars
    status = validate_messaging_caller_context(ctx, kRequireIdempotency, error);
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::INVALID_ARGUMENT);

    ctx.idempotency_token = "valid-idempotency-token-12345";
    status = validate_messaging_caller_context(ctx, kRequireIdempotency, error);
    EXPECT_TRUE(status.ok());
}

TEST(MessagingCallerContextTest, ValidateAllCombinedRequirements) {
    MessagingCallerContext ctx;
    ctx.base.peer_identity = "gateway";
    ctx.base.correlation_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000";
    ctx.base.user_id = "550e8400-e29b-41d4-a716-446655440000";
    ctx.base.device_id = "a0b1c2d3-e4f5-6789-abcd-ef0123456789";
    ctx.idempotency_token = "send-message-token-987654321";

    const uint32_t all_flags =
        kRequireAuthorizedPeer | kRequireCorrelationId | kRequireUserId | kRequireDeviceId | kRequireIdempotency;

    std::string error;
    auto status = validate_messaging_caller_context(ctx, all_flags, error);
    EXPECT_TRUE(status.ok());
    EXPECT_TRUE(error.empty());
}

} // namespace
} // namespace securecloud::messaging::service
