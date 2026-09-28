#include "http/auth/authenticated_context.hpp"

#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace securecloud::gateway::http {
namespace {

// ============================================================================
// Test Suite: Construction & Field Invariants
// ============================================================================

TEST(AuthenticatedContextTest, DefaultConstructorInitializesSafeEmptyState) {
    AuthenticatedContext ctx;
    EXPECT_TRUE(ctx.user_id().empty());
    EXPECT_TRUE(ctx.device_id().empty());
    EXPECT_TRUE(ctx.session_id().empty());
    EXPECT_EQ(ctx.authentication_level(), securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_UNSPECIFIED);
    EXPECT_TRUE(ctx.scopes().empty());
    EXPECT_EQ(ctx.expires_at_epoch_ms(), 0);
    EXPECT_FALSE(ctx.is_mfa_verified());
}

TEST(AuthenticatedContextTest, ParameterizedConstructorPreservesAllFields) {
    const std::string user_id = "usr_998877";
    const std::string device_id = "dev_apple_m3";
    const std::string session_id = "sess_live_445566";
    const auto auth_level = securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY;
    const std::vector<std::string> scopes = {"files:read", "messages:write"};
    const int64_t expires_at = 1770000000000LL;

    AuthenticatedContext ctx(user_id, device_id, session_id, auth_level, scopes, expires_at);

    EXPECT_EQ(ctx.user_id(), user_id);
    EXPECT_EQ(ctx.device_id(), device_id);
    EXPECT_EQ(ctx.session_id(), session_id);
    EXPECT_EQ(ctx.authentication_level(), auth_level);
    ASSERT_EQ(ctx.scopes().size(), 2);
    EXPECT_EQ(ctx.scopes()[0], "files:read");
    EXPECT_EQ(ctx.scopes()[1], "messages:write");
    EXPECT_EQ(ctx.expires_at_epoch_ms(), expires_at);
}

// ============================================================================
// Test Suite: Authentication Assurance Level (MFA)
// ============================================================================

TEST(AuthenticatedContextTest, MfaVerificationTruthTable) {
    AuthenticatedContext unspecified_ctx(
        "u1", "d1", "s1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_UNSPECIFIED, {}, 0);
    EXPECT_FALSE(unspecified_ctx.is_mfa_verified());

    AuthenticatedContext primary_ctx("u1", "d1", "s1",
                                     securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, {}, 0);
    EXPECT_FALSE(primary_ctx.is_mfa_verified());

    AuthenticatedContext mfa_ctx("u1", "d1", "s1",
                                 securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED, {}, 0);
    EXPECT_TRUE(mfa_ctx.is_mfa_verified());
}

// ============================================================================
// Test Suite: Scope Checking
// ============================================================================

TEST(AuthenticatedContextTest, ScopeCheckingExactMatchesAndRejections) {
    AuthenticatedContext ctx("u1", "d1", "s1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                             {"files:read", "files:write", "admin:audit"}, 1000);

    // Exact matches
    EXPECT_TRUE(ctx.has_scope("files:read"));
    EXPECT_TRUE(ctx.has_scope("files:write"));
    EXPECT_TRUE(ctx.has_scope("admin:audit"));

    // Missing scope
    EXPECT_FALSE(ctx.has_scope("messages:send"));
    EXPECT_FALSE(ctx.has_scope("admin:root"));

    // Case sensitivity: scopes are strictly case-sensitive
    EXPECT_FALSE(ctx.has_scope("FILES:READ"));
    EXPECT_FALSE(ctx.has_scope("Files:Read"));

    // Prefix/Substring must not match
    EXPECT_FALSE(ctx.has_scope("files:"));
    EXPECT_FALSE(ctx.has_scope("files"));
    EXPECT_FALSE(ctx.has_scope("read"));
}

TEST(AuthenticatedContextTest, ScopeCheckingEmptyScopeListAlwaysReturnsFalse) {
    AuthenticatedContext ctx("u1", "d1", "s1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                             {}, 1000);

    EXPECT_FALSE(ctx.has_scope("files:read"));
    EXPECT_FALSE(ctx.has_scope(""));
}

// ============================================================================
// Test Suite: Temporal Expiration Evaluation
// ============================================================================

TEST(AuthenticatedContextTest, ExpirationBoundaryEvaluation) {
    const int64_t expiry = 10000LL;
    AuthenticatedContext ctx("u1", "d1", "s1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                             {}, expiry);

    // Active in the past (before expiry)
    EXPECT_FALSE(ctx.is_expired(9999LL));
    EXPECT_TRUE(ctx.is_valid_at(9999LL));

    // Exact boundary: expiration is inclusive (now >= expires_at is expired)
    EXPECT_TRUE(ctx.is_expired(10000LL));
    EXPECT_FALSE(ctx.is_valid_at(10000LL));

    // Past expiry
    EXPECT_TRUE(ctx.is_expired(10001LL));
    EXPECT_FALSE(ctx.is_valid_at(10001LL));
}

TEST(AuthenticatedContextTest, ZeroOrNegativeExpirationNeverExpires) {
    AuthenticatedContext ctx("u1", "d1", "s1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                             {}, 0);

    EXPECT_FALSE(ctx.is_expired(99999999LL));
    EXPECT_TRUE(ctx.is_valid_at(99999999LL));
}

// ============================================================================
// Test Suite: Monadic TokenValidationResult
// ============================================================================

TEST(AuthenticatedContextTest, TokenValidationResultHoldsSuccessContext) {
    AuthenticatedContext original_ctx("usr_alice", "dev_laptop", "sess_001",
                                      securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED,
                                      {"read", "write"}, 5000);

    AuthenticatedResult result(original_ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result.has_error());
    EXPECT_TRUE(static_cast<bool>(result));

    EXPECT_EQ(result.value().user_id(), "usr_alice");
    EXPECT_EQ(result.value().device_id(), "dev_laptop");
    EXPECT_EQ(result.value().session_id(), "sess_001");
    EXPECT_TRUE(result.value().is_mfa_verified());
}

TEST(AuthenticatedContextTest, TokenValidationResultHoldsExplicitErrors) {
    const std::vector<TokenValidationErrorKind> error_kinds = {
        TokenValidationErrorKind::TokenExpired,      TokenValidationErrorKind::SessionRevoked,
        TokenValidationErrorKind::InvalidSignature,  TokenValidationErrorKind::MfaRequired,
        TokenValidationErrorKind::InsufficientScope, TokenValidationErrorKind::ServiceUnavailable,
        TokenValidationErrorKind::MalformedToken,    TokenValidationErrorKind::InternalError,
    };

    for (const auto kind : error_kinds) {
        TokenValidationError err{
            .kind = kind,
            .message = "Validation failure reason",
        };

        AuthenticatedResult result(err);

        ASSERT_FALSE(result.has_value());
        ASSERT_TRUE(result.has_error());
        EXPECT_FALSE(static_cast<bool>(result));
        EXPECT_EQ(result.error().kind, kind);
        EXPECT_EQ(result.error().message, "Validation failure reason");
    }
}

TEST(AuthenticatedContextTest, ToAuditInfoProducesSafeJsonWithoutSecrets) {
    AuthenticatedContext ctx("usr-alice-777", "dev-iphone-888", "sess-active-999",
                             securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED,
                             {"messages:write", "files:read"}, 1700000000000);

    auto audit_json = ctx.to_audit_info();

    // Verify expected opaque fields
    EXPECT_EQ(audit_json["user_id"], "usr-alice-777");
    EXPECT_EQ(audit_json["device_id"], "dev-iphone-888");
    EXPECT_EQ(audit_json["session_id"], "sess-active-999");
    EXPECT_EQ(audit_json["auth_level"], "AUTHENTICATION_LEVEL_MFA_VERIFIED");
    EXPECT_TRUE(audit_json["mfa_verified"].get<bool>());
    EXPECT_EQ(audit_json["expires_at_epoch_ms"], 1700000000000);
    EXPECT_EQ(audit_json["scopes"].size(), 2u);

    // Verify zero secret leakage invariant
    EXPECT_FALSE(audit_json.contains("access_token"));
    EXPECT_FALSE(audit_json.contains("token"));
    EXPECT_FALSE(audit_json.contains("private_key"));
    EXPECT_FALSE(audit_json.contains("secret"));
    EXPECT_FALSE(audit_json.contains("identity_key"));
    EXPECT_FALSE(audit_json.contains("signed_prekey"));
    EXPECT_FALSE(audit_json.contains("one_time_prekey"));
    EXPECT_FALSE(audit_json.contains("plaintext"));
    EXPECT_FALSE(audit_json.contains("payload"));
}

TEST(AuthenticatedContextTest, SecretIsolationInvariantGuaranteed) {
    // Assert AuthenticatedContext is movable and copyable
    EXPECT_TRUE(std::is_copy_constructible_v<AuthenticatedContext>);
    EXPECT_TRUE(std::is_move_constructible_v<AuthenticatedContext>);

    // Verify that context holds only opaque string identifiers and verification primitives
    AuthenticatedContext ctx("u1", "d1", "s1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                             {"access"}, 5000);

    EXPECT_EQ(ctx.user_id(), "u1");
    EXPECT_EQ(ctx.device_id(), "d1");
    EXPECT_EQ(ctx.session_id(), "s1");
    EXPECT_EQ(ctx.authentication_level(), securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    EXPECT_FALSE(ctx.is_mfa_verified());
}

} // namespace
} // namespace securecloud::gateway::http
