#include "http/auth/gateway_security_policy.hpp"

#include <chrono>
#include <future>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

namespace securecloud::gateway::http {
namespace {

TEST(GatewaySecurityPolicyTest, DefaultPolicyAllowsCanonicalPublicRoutes) {
    auto policy = GatewaySecurityPolicy::create_default();

    const std::vector<std::pair<std::string, std::string>> public_endpoints = {
        {"GET", "/health/live"},        {"GET", "/health/ready"},         {"POST", "/api/v1/auth/register"},
        {"POST", "/api/v1/auth/login"}, {"POST", "/api/v1/auth/refresh"},
    };

    for (const auto& [method, path] : public_endpoints) {
        auto rule = policy.evaluate(method, path);
        EXPECT_EQ(rule.access, RouteAccess::Public) << "Failed for " << method << " " << path;
        EXPECT_TRUE(rule.is_public()) << "Failed for " << method << " " << path;
        EXPECT_FALSE(rule.requires_mfa()) << "Failed for " << method << " " << path;
    }
}

TEST(GatewaySecurityPolicyTest, DefaultPolicyProtectsStandardRoutes) {
    auto policy = GatewaySecurityPolicy::create_default();

    const std::vector<std::pair<std::string, std::string>> protected_endpoints = {
        {"POST", "/api/v1/messages/send"},  {"GET", "/api/v1/messages/inbox"}, {"POST", "/api/v1/files/upload"},
        {"GET", "/api/v1/files/chunk-123"}, {"POST", "/api/v1/auth/revoke"},   {"GET", "/api/v1/auth/me"},
    };

    for (const auto& [method, path] : protected_endpoints) {
        auto rule = policy.evaluate(method, path);
        EXPECT_EQ(rule.access, RouteAccess::Protected) << "Failed for " << method << " " << path;
        EXPECT_FALSE(rule.is_public()) << "Failed for " << method << " " << path;
        EXPECT_FALSE(rule.requires_mfa()) << "Failed for " << method << " " << path;
    }
}

TEST(GatewaySecurityPolicyTest, DefaultPolicyRequiresMfaForSensitiveRoutes) {
    auto policy = GatewaySecurityPolicy::create_default();

    const std::vector<std::pair<std::string, std::string>> sensitive_endpoints = {
        {"POST", "/api/v1/auth/device/register"},
        {"GET", "/api/v1/auth/security/keys"},
        {"POST", "/api/v1/auth/security/rotate-keys"},
    };

    for (const auto& [method, path] : sensitive_endpoints) {
        auto rule = policy.evaluate(method, path);
        EXPECT_EQ(rule.access, RouteAccess::Sensitive) << "Failed for " << method << " " << path;
        EXPECT_FALSE(rule.is_public()) << "Failed for " << method << " " << path;
        EXPECT_TRUE(rule.requires_mfa()) << "Failed for " << method << " " << path;
        EXPECT_EQ(rule.min_auth_level, securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    }
}

TEST(GatewaySecurityPolicyTest, FailClosedDefaultProtectsUnknownRoutes) {
    auto policy = GatewaySecurityPolicy::create_default();

    const std::vector<std::pair<std::string, std::string>> unmapped_routes = {
        {"GET", "/admin/secret"},
        {"POST", "/api/v2/unregistered"},
        {"DELETE", "/api/v1/files/destroy"},
        {"GET", "/internal/debug"},
    };

    for (const auto& [method, path] : unmapped_routes) {
        auto rule = policy.evaluate(method, path);
        EXPECT_EQ(rule.access, RouteAccess::Protected) << "Failed to fail closed for " << method << " " << path;
        EXPECT_FALSE(rule.is_public()) << "Unmapped route must never be public: " << method << " " << path;
    }
}

TEST(GatewaySecurityPolicyTest, ExactRouteMatchTakesPrecedenceOverPrefix) {
    GatewaySecurityPolicy policy;

    // Broad prefix is Protected
    policy.add_rule("*", "/api/v1/users/*", RouteAccess::Protected);

    // Specific exact subpath is Public
    policy.add_rule("GET", "/api/v1/users/public-avatar", RouteAccess::Public);

    auto public_rule = policy.evaluate("GET", "/api/v1/users/public-avatar");
    EXPECT_EQ(public_rule.access, RouteAccess::Public);

    auto protected_rule = policy.evaluate("GET", "/api/v1/users/settings");
    EXPECT_EQ(protected_rule.access, RouteAccess::Protected);
}

TEST(GatewaySecurityPolicyTest, LongestPrefixTakesPrecedenceOverShorterPrefix) {
    GatewaySecurityPolicy policy;

    policy.add_rule("*", "/api/v1/auth/*", RouteAccess::Protected);
    policy.add_rule("*", "/api/v1/auth/security/*", RouteAccess::Sensitive);

    auto general_rule = policy.evaluate("GET", "/api/v1/auth/tokens");
    EXPECT_EQ(general_rule.access, RouteAccess::Protected);

    auto specific_rule = policy.evaluate("GET", "/api/v1/auth/security/audit-keys");
    EXPECT_EQ(specific_rule.access, RouteAccess::Sensitive);
    EXPECT_TRUE(specific_rule.requires_mfa());
}

TEST(GatewaySecurityPolicyTest, PathNormalizationStripsQueryAndTrailingSlash) {
    GatewaySecurityPolicy policy;
    policy.add_rule("GET", "/health/live", RouteAccess::Public);
    policy.add_rule("POST", "/api/v1/auth/login", RouteAccess::Public);

    EXPECT_EQ(policy.evaluate("GET", "/health/live?probe=k8s&timeout=5").access, RouteAccess::Public);
    EXPECT_EQ(policy.evaluate("POST", "/api/v1/auth/login/").access, RouteAccess::Public);
    EXPECT_EQ(policy.evaluate("POST", "/api/v1/auth/login/?device=mobile").access, RouteAccess::Public);
}

TEST(GatewaySecurityPolicyTest, MethodSpecificRulesHonorHttpVerb) {
    GatewaySecurityPolicy policy;
    policy.add_rule("GET", "/api/v1/items", RouteAccess::Public);
    policy.add_rule("POST", "/api/v1/items", RouteAccess::Protected);

    EXPECT_EQ(policy.evaluate("GET", "/api/v1/items").access, RouteAccess::Public);
    EXPECT_EQ(policy.evaluate("POST", "/api/v1/items").access, RouteAccess::Protected);
    EXPECT_EQ(policy.evaluate("DELETE", "/api/v1/items").access, RouteAccess::Protected); // Fail-closed default
}

TEST(GatewaySecurityPolicyTest, RuleSatisfiesEvaluatesAssuranceAndScopes) {
    RouteSecurityRule sensitive_rule{
        .access = RouteAccess::Sensitive,
        .min_auth_level = securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED,
        .required_scopes = {"files:write", "files:audit"},
    };

    // Case 1: Primary auth level lacks MFA
    AuthenticatedContext primary_ctx("usr-1", "dev-1", "s-1",
                                     securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                                     {"files:write", "files:audit"}, 100000);
    EXPECT_FALSE(sensitive_rule.satisfies(primary_ctx));

    // Case 2: MFA verified but missing a required scope
    AuthenticatedContext missing_scope_ctx(
        "usr-1", "dev-1", "s-1", securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED,
        {"files:write"}, 100000);
    EXPECT_FALSE(sensitive_rule.satisfies(missing_scope_ctx));

    // Case 3: MFA verified and all required scopes present
    AuthenticatedContext valid_ctx("usr-1", "dev-1", "s-1",
                                   securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED,
                                   {"files:write", "files:audit", "extra:scope"}, 100000);
    EXPECT_TRUE(sensitive_rule.satisfies(valid_ctx));
}

TEST(GatewaySecurityPolicyTest, ConcurrentEvaluationsAreThreadSafe) {
    auto policy = GatewaySecurityPolicy::create_default();

    constexpr int kNumThreads = 8;
    constexpr int kItersPerThread = 200;
    std::vector<std::future<void>> futures;
    futures.reserve(kNumThreads);

    for (int t = 0; t < kNumThreads; ++t) {
        futures.push_back(std::async(std::launch::async, [&policy]() -> void {
            for (int i = 0; i < kItersPerThread; ++i) {
                auto r1 = policy.evaluate("GET", "/health/live");
                EXPECT_TRUE(r1.is_public());

                auto r2 = policy.evaluate("POST", "/api/v1/auth/device/register");
                EXPECT_TRUE(r2.requires_mfa());

                auto r3 = policy.evaluate("GET", "/api/v1/messages/thread-" + std::to_string(i));
                EXPECT_EQ(r3.access, RouteAccess::Protected);

                auto r4 = policy.evaluate("GET", "/unknown/route/" + std::to_string(i));
                EXPECT_EQ(r4.access, RouteAccess::Protected);
            }
        }));
    }

    for (auto& f : futures) {
        f.get();
    }
}

} // namespace
} // namespace securecloud::gateway::http
