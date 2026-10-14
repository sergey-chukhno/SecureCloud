#include "securecloud/grpc/caller_context.hpp"

#include <deque>
#include <grpc/support/time.h>
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

    void set_deadline(gpr_timespec deadline) { ctx_->deadline_ = deadline; }

    void set_cancelled(bool cancelled = true) { ctx_->marked_cancelled_.store(cancelled, std::memory_order_release); }

  private:
    ::grpc::ServerContext* ctx_;
    std::deque<std::string> stored_strings_;
};

} // namespace grpc::testing

namespace securecloud::common::rpc {
namespace {

// ============================================================================
// TestAuthContext implementation for synthetic peer identities
// ============================================================================

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
// UUID Format Validation Tests (RFC 4122)
// ============================================================================

TEST(CallerContextTest, ValidUuidsPass) {
    EXPECT_TRUE(is_valid_uuid("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000"));
    EXPECT_TRUE(is_valid_uuid("550e8400-e29b-41d4-a716-446655440000"));
    EXPECT_TRUE(is_valid_uuid("550E8400-E29B-41D4-A716-446655440000"));
    EXPECT_TRUE(is_valid_uuid("a0b1c2d3-e4f5-6789-abcd-ef0123456789"));
}

TEST(CallerContextTest, InvalidUuidLengthRejected) {
    EXPECT_FALSE(is_valid_uuid(""));
    EXPECT_FALSE(is_valid_uuid("550e8400-e29b-41d4-a716-44665544000"));   // 35 chars
    EXPECT_FALSE(is_valid_uuid("550e8400-e29b-41d4-a716-4466554400000")); // 37 chars
}

TEST(CallerContextTest, InvalidUuidHyphenPlacementsRejected) {
    // 32-hex characters without hyphens
    EXPECT_FALSE(is_valid_uuid("550e8400e29b41d4a716446655440000"));
    // Hyphen off by one
    EXPECT_FALSE(is_valid_uuid("550e840-0e29b-41d4-a716-446655440000"));
    EXPECT_FALSE(is_valid_uuid("550e8400-e29-b41d4-a716-446655440000"));
}

TEST(CallerContextTest, InvalidUuidCharactersRejected) {
    EXPECT_FALSE(is_valid_uuid("550e8400-e29b-41d4-a716-44665544000g")); // 'g' non-hex
    EXPECT_FALSE(is_valid_uuid("550e8400-e29b-41d4-a716-44665544000z")); // 'z' non-hex
    EXPECT_FALSE(is_valid_uuid("550e8400-e29b-41d4-a716-44665544 000")); // space
    EXPECT_FALSE(is_valid_uuid("550e8400-e29b-41d4-a716-44665544!000")); // punctuation
}

// ============================================================================
// Peer SAN Identity Extraction Tests
// ============================================================================

TEST(CallerContextTest, ExtractPeerIdentityFromNullContextReturnsAnonymous) {
    EXPECT_EQ(extract_peer_identity(static_cast<const ::grpc::AuthContext*>(nullptr)), "anonymous");
}

TEST(CallerContextTest, ExtractPeerIdentityFromUnauthenticatedContextReturnsAnonymous) {
    TestAuthContext unauth_ctx(false);
    EXPECT_EQ(extract_peer_identity(&unauth_ctx), "anonymous");
}

TEST(CallerContextTest, ExtractPeerIdentityFromSanProperty) {
    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});
    EXPECT_EQ(extract_peer_identity(&gateway_ctx), "gateway");

    TestAuthContext raw_gateway_ctx(true, {{"x509_subject_alternative_name", "gateway"}});
    EXPECT_EQ(extract_peer_identity(&raw_gateway_ctx), "gateway");

    TestAuthContext auth_ctx(true, {{"x509_subject_alternative_name", "DNS:auth"}});
    EXPECT_EQ(extract_peer_identity(&auth_ctx), "auth");

    TestAuthContext messaging_ctx(true, {{"x509_subject_alternative_name", "DNS:messaging"}});
    EXPECT_EQ(extract_peer_identity(&messaging_ctx), "messaging");

    TestAuthContext files_ctx(true, {{"x509_subject_alternative_name", "DNS:files"}});
    EXPECT_EQ(extract_peer_identity(&files_ctx), "files");
}

TEST(CallerContextTest, ExtractPeerIdentityWithoutSanReturnsUnknownPeer) {
    TestAuthContext no_san_ctx(true, {{"x509_common_name", "messaging"}});
    EXPECT_EQ(extract_peer_identity(&no_san_ctx), "unknown_peer");
}

// ============================================================================
// Service Peer Authorization Tests
// ============================================================================

TEST(CallerContextTest, IsAuthorizedServicePeerStringView) {
    EXPECT_TRUE(is_authorized_service_peer("gateway"));
    EXPECT_TRUE(is_authorized_service_peer("auth"));
    EXPECT_TRUE(is_authorized_service_peer("messaging"));
    EXPECT_TRUE(is_authorized_service_peer("files"));

    EXPECT_FALSE(is_authorized_service_peer(""));
    EXPECT_FALSE(is_authorized_service_peer("anonymous"));
    EXPECT_FALSE(is_authorized_service_peer("unknown_peer"));
    EXPECT_FALSE(is_authorized_service_peer("untrusted-service"));
    EXPECT_FALSE(is_authorized_service_peer("gateway-admin"));
}

TEST(CallerContextTest, IsAuthorizedServicePeerAuthContext) {
    EXPECT_FALSE(is_authorized_service_peer(static_cast<const ::grpc::AuthContext*>(nullptr)));

    TestAuthContext unauth_ctx(false);
    EXPECT_FALSE(is_authorized_service_peer(&unauth_ctx));

    TestAuthContext gateway_ctx(true, {{"x509_subject_alternative_name", "DNS:gateway"}});
    EXPECT_TRUE(is_authorized_service_peer(&gateway_ctx));

    TestAuthContext rogue_ctx(true, {{"x509_subject_alternative_name", "DNS:untrusted"}});
    EXPECT_FALSE(is_authorized_service_peer(&rogue_ctx));
}

TEST(CallerContextTest, IsAuthorizedServicePeerServerContext) {
    EXPECT_FALSE(is_authorized_service_peer(static_cast<const ::grpc::ServerContext*>(nullptr)));

    ::grpc::ServerContext empty_ctx;
    EXPECT_FALSE(is_authorized_service_peer(&empty_ctx));

    ::grpc::ServerContext gateway_server_ctx;
    ::grpc::testing::ServerContextTestSpouse spouse(&gateway_server_ctx);
    spouse.set_auth_context(std::make_shared<TestAuthContext>(
        true, std::vector<std::pair<std::string, std::string>>{{"x509_subject_alternative_name", "DNS:gateway"}}));
    EXPECT_TRUE(is_authorized_service_peer(&gateway_server_ctx));
}

// ============================================================================
// Extract Caller Context Tests
// ============================================================================

TEST(CallerContextTest, ExtractCallerContextNullReturnsDefault) {
    CallerContext ctx = extract_caller_context(nullptr);
    EXPECT_TRUE(ctx.user_id.empty());
    EXPECT_TRUE(ctx.device_id.empty());
    EXPECT_TRUE(ctx.correlation_id.empty());
    EXPECT_EQ(ctx.peer_identity, "anonymous");
}

TEST(CallerContextTest, ExtractCallerContextFromMetadata) {
    ::grpc::ServerContext server_ctx;
    ::grpc::testing::ServerContextTestSpouse spouse(&server_ctx);

    spouse.add_client_metadata("x-correlation-id", "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    spouse.add_client_metadata("x-user-id", "550e8400-e29b-41d4-a716-446655440000");
    spouse.add_client_metadata("x-device-id", "a0b1c2d3-e4f5-6789-abcd-ef0123456789");
    spouse.set_auth_context(std::make_shared<TestAuthContext>(
        true, std::vector<std::pair<std::string, std::string>>{{"x509_subject_alternative_name", "DNS:gateway"}}));

    CallerContext ctx = extract_caller_context(&server_ctx);
    EXPECT_EQ(ctx.correlation_id, "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    EXPECT_EQ(ctx.user_id, "550e8400-e29b-41d4-a716-446655440000");
    EXPECT_EQ(ctx.device_id, "a0b1c2d3-e4f5-6789-abcd-ef0123456789");
    EXPECT_EQ(ctx.peer_identity, "gateway");
}

TEST(CallerContextTest, ExtractCallerContextFallbackToRequestId) {
    ::grpc::ServerContext server_ctx;
    ::grpc::testing::ServerContextTestSpouse spouse(&server_ctx);

    spouse.add_client_metadata("x-request-id", "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");

    CallerContext ctx = extract_caller_context(&server_ctx);
    EXPECT_EQ(ctx.correlation_id, "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
}

TEST(CallerContextTest, ExtractCallerContextCorrelationIdPreferredOverRequestId) {
    ::grpc::ServerContext server_ctx;
    ::grpc::testing::ServerContextTestSpouse spouse(&server_ctx);

    spouse.add_client_metadata("x-correlation-id", "preferred-correlation-id");
    spouse.add_client_metadata("x-request-id", "fallback-request-id");

    CallerContext ctx = extract_caller_context(&server_ctx);
    EXPECT_EQ(ctx.correlation_id, "preferred-correlation-id");
}

// ============================================================================
// Deadline and Cancellation Check Tests
// ============================================================================

constexpr int64_t k_test_offset_seconds = 60;

TEST(CallerContextDeadlineTest, NullContextReturnsOk) {
    auto status = check_deadline_and_cancellation(nullptr);
    EXPECT_TRUE(status.ok());

    ::grpc::Status out_status;
    bool triggered = check_deadline_and_cancellation(nullptr, out_status);
    EXPECT_FALSE(triggered);
    EXPECT_TRUE(out_status.ok());
}

TEST(CallerContextDeadlineTest, ActiveContextWithinDeadlineReturnsOk) {
    ::grpc::ServerContext server_ctx;
    ::grpc::testing::ServerContextTestSpouse spouse(&server_ctx);

    const gpr_timespec future_dl =
        gpr_time_add(gpr_now(GPR_CLOCK_REALTIME), gpr_time_from_seconds(k_test_offset_seconds, GPR_TIMESPAN));
    spouse.set_deadline(future_dl);

    auto status = check_deadline_and_cancellation(&server_ctx);
    EXPECT_TRUE(status.ok());

    ::grpc::Status out_status;
    bool triggered = check_deadline_and_cancellation(&server_ctx, out_status);
    EXPECT_FALSE(triggered);
    EXPECT_TRUE(out_status.ok());
}

TEST(CallerContextDeadlineTest, DefaultContextWithoutDeadlineReturnsOk) {
    ::grpc::ServerContext server_ctx;

    auto status = check_deadline_and_cancellation(&server_ctx);
    EXPECT_TRUE(status.ok());

    ::grpc::Status out_status;
    bool triggered = check_deadline_and_cancellation(&server_ctx, out_status);
    EXPECT_FALSE(triggered);
    EXPECT_TRUE(out_status.ok());
}

TEST(CallerContextDeadlineTest, ExpiredDeadlineReturnsDeadlineExceeded) {
    ::grpc::ServerContext server_ctx;
    ::grpc::testing::ServerContextTestSpouse spouse(&server_ctx);

    const gpr_timespec past_dl =
        gpr_time_sub(gpr_now(GPR_CLOCK_REALTIME), gpr_time_from_seconds(k_test_offset_seconds, GPR_TIMESPAN));
    spouse.set_deadline(past_dl);

    auto status = check_deadline_and_cancellation(&server_ctx);
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::DEADLINE_EXCEEDED);

    ::grpc::Status out_status;
    bool triggered = check_deadline_and_cancellation(&server_ctx, out_status);
    EXPECT_TRUE(triggered);
    EXPECT_EQ(out_status.error_code(), ::grpc::StatusCode::DEADLINE_EXCEEDED);
}

TEST(CallerContextDeadlineTest, CancelledContextReturnsCancelled) {
    ::grpc::ServerContext server_ctx;
    ::grpc::testing::ServerContextTestSpouse spouse(&server_ctx);
    spouse.set_cancelled(true);

    auto status = check_deadline_and_cancellation(&server_ctx);
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::CANCELLED);

    ::grpc::Status out_status;
    bool triggered = check_deadline_and_cancellation(&server_ctx, out_status);
    EXPECT_TRUE(triggered);
    EXPECT_EQ(out_status.error_code(), ::grpc::StatusCode::CANCELLED);
}

} // namespace
} // namespace securecloud::common::rpc
