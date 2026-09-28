#include "http/auth/header_sanitizer.hpp"

#include <gtest/gtest.h>
#include <httplib.h>

namespace securecloud::gateway::http {
namespace {

TEST(HeaderSanitizerTest, DetectsExactIdentityHeadersCaseInsensitively) {
    EXPECT_TRUE(HeaderSanitizer::is_identity_header("x-user-id"));
    EXPECT_TRUE(HeaderSanitizer::is_identity_header("X-User-Id"));
    EXPECT_TRUE(HeaderSanitizer::is_identity_header("X-USER-ID"));
    EXPECT_TRUE(HeaderSanitizer::is_identity_header("x-device-id"));
    EXPECT_TRUE(HeaderSanitizer::is_identity_header("X-DEVICE-ID"));
    EXPECT_TRUE(HeaderSanitizer::is_identity_header("x-auth-level"));
    EXPECT_TRUE(HeaderSanitizer::is_identity_header("X-Auth-Level"));
    EXPECT_TRUE(HeaderSanitizer::is_identity_header("x-scopes"));
    EXPECT_TRUE(HeaderSanitizer::is_identity_header("X-SCOPES"));
    EXPECT_TRUE(HeaderSanitizer::is_identity_header("x-session-id"));
    EXPECT_TRUE(HeaderSanitizer::is_identity_header("X-Session-ID"));
    EXPECT_TRUE(HeaderSanitizer::is_identity_header("x-authenticated-user"));
    EXPECT_TRUE(HeaderSanitizer::is_identity_header("x-authenticated-device"));
    EXPECT_TRUE(HeaderSanitizer::is_identity_header("x-authenticated-scope"));
    EXPECT_TRUE(HeaderSanitizer::is_identity_header("x-authenticated-scopes"));
    EXPECT_TRUE(HeaderSanitizer::is_identity_header("x-authenticated-level"));
}

TEST(HeaderSanitizerTest, DetectsPrefixedIdentityHeadersCaseInsensitively) {
    EXPECT_TRUE(HeaderSanitizer::is_identity_header("x-authenticated-role"));
    EXPECT_TRUE(HeaderSanitizer::is_identity_header("X-AUTHENTICATED-PERMISSIONS"));
    EXPECT_TRUE(HeaderSanitizer::is_identity_header("x-authenticated-claims"));
    EXPECT_TRUE(HeaderSanitizer::is_identity_header("x-securecloud-identity-caller"));
    EXPECT_TRUE(HeaderSanitizer::is_identity_header("X-SECURECLOUD-IDENTITY-HASH"));
}

TEST(HeaderSanitizerTest, PreservesLegitimateHeaders) {
    EXPECT_FALSE(HeaderSanitizer::is_identity_header("Authorization"));
    EXPECT_FALSE(HeaderSanitizer::is_identity_header("authorization"));
    EXPECT_FALSE(HeaderSanitizer::is_identity_header("x-request-id"));
    EXPECT_FALSE(HeaderSanitizer::is_identity_header("X-Request-Id"));
    EXPECT_FALSE(HeaderSanitizer::is_identity_header("Content-Type"));
    EXPECT_FALSE(HeaderSanitizer::is_identity_header("content-type"));
    EXPECT_FALSE(HeaderSanitizer::is_identity_header("Host"));
    EXPECT_FALSE(HeaderSanitizer::is_identity_header("User-Agent"));
    EXPECT_FALSE(HeaderSanitizer::is_identity_header("Accept"));
    EXPECT_FALSE(HeaderSanitizer::is_identity_header("x-correlation-id"));
    EXPECT_FALSE(HeaderSanitizer::is_identity_header("x-forwarded-for"));
}

TEST(HeaderSanitizerTest, SanitizesRequestHeadersInPlace) {
    httplib::Request req;
    req.set_header("Authorization", "Bearer valid-token");
    req.set_header("x-request-id", "req-12345");
    req.set_header("Content-Type", "application/json");

    // Injected spoofed identity headers
    req.set_header("X-User-Id", "attacker-admin");
    req.set_header("x-device-id", "fake-device-999");
    req.set_header("X-Auth-Level", "AUTHENTICATION_LEVEL_MFA_VERIFIED");
    req.set_header("x-scopes", "admin,root");
    req.set_header("x-authenticated-role", "superuser");
    req.set_header("x-securecloud-identity-bypass", "true");

    HeaderSanitizer::sanitize(req);

    // Assert spoofed headers were stripped
    EXPECT_FALSE(req.has_header("X-User-Id"));
    EXPECT_FALSE(req.has_header("x-user-id"));
    EXPECT_FALSE(req.has_header("x-device-id"));
    EXPECT_FALSE(req.has_header("X-Auth-Level"));
    EXPECT_FALSE(req.has_header("x-scopes"));
    EXPECT_FALSE(req.has_header("x-authenticated-role"));
    EXPECT_FALSE(req.has_header("x-securecloud-identity-bypass"));

    // Assert legitimate headers were preserved
    EXPECT_TRUE(req.has_header("Authorization"));
    EXPECT_EQ(req.get_header_value("Authorization"), "Bearer valid-token");
    EXPECT_TRUE(req.has_header("x-request-id"));
    EXPECT_EQ(req.get_header_value("x-request-id"), "req-12345");
    EXPECT_TRUE(req.has_header("Content-Type"));
    EXPECT_EQ(req.get_header_value("Content-Type"), "application/json");
}

TEST(HeaderSanitizerTest, HandlesEmptyOrHeaderlessRequestSafely) {
    httplib::Request req;
    EXPECT_NO_THROW(HeaderSanitizer::sanitize(req));
    EXPECT_TRUE(req.headers.empty());
}

TEST(HeaderSanitizerTest, RemovesDuplicateUntrustedHeaders) {
    httplib::Request req;
    req.headers.emplace("x-user-id", "user1");
    req.headers.emplace("X-User-Id", "user2");
    req.headers.emplace("X-USER-ID", "user3");
    req.set_header("x-request-id", "req-test");

    HeaderSanitizer::sanitize(req);

    EXPECT_FALSE(req.has_header("x-user-id"));
    EXPECT_TRUE(req.has_header("x-request-id"));
    EXPECT_EQ(req.headers.size(), 1u);
}

} // namespace
} // namespace securecloud::gateway::http
