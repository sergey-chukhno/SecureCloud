#include "http/auth/authenticated_context.hpp"
#include "http/auth/scope_matcher.hpp"

#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace securecloud::gateway::http {
namespace {

TEST(ScopeMatcherTest, ExactMatchEvaluatesCorrectly) {
    EXPECT_TRUE(ScopeMatcher::matches("messages:read", "messages:read"));
    EXPECT_TRUE(ScopeMatcher::matches("auth:revoke", "auth:revoke"));
    EXPECT_TRUE(ScopeMatcher::matches("access", "access"));

    EXPECT_FALSE(ScopeMatcher::matches("messages:read", "messages:write"));
    EXPECT_FALSE(ScopeMatcher::matches("messages:read", "files:read"));
    EXPECT_FALSE(ScopeMatcher::matches("access", "other"));
}

TEST(ScopeMatcherTest, GlobalWildcardMatchesAnyNonEmptyScope) {
    EXPECT_TRUE(ScopeMatcher::matches("*", "messages:read"));
    EXPECT_TRUE(ScopeMatcher::matches("*", "files:upload"));
    EXPECT_TRUE(ScopeMatcher::matches("*", "auth:revoke"));
    EXPECT_TRUE(ScopeMatcher::matches("*", "audit:read"));
    EXPECT_TRUE(ScopeMatcher::matches("*", "arbitrary_scope"));

    // Global wildcard cannot match empty required scope
    EXPECT_FALSE(ScopeMatcher::matches("*", ""));
}

TEST(ScopeMatcherTest, DomainWildcardMatchesActionsWithinDomain) {
    EXPECT_TRUE(ScopeMatcher::matches("messages:*", "messages:read"));
    EXPECT_TRUE(ScopeMatcher::matches("messages:*", "messages:send"));
    EXPECT_TRUE(ScopeMatcher::matches("messages:*", "messages:delete"));
    EXPECT_TRUE(ScopeMatcher::matches("messages:*", "messages:conversation:create"));

    EXPECT_TRUE(ScopeMatcher::matches("files:*", "files:upload"));
    EXPECT_TRUE(ScopeMatcher::matches("files:*", "files:download"));
}

TEST(ScopeMatcherTest, DomainWildcardRejectsCrossDomainAndMalformedActions) {
    // Other domains must be rejected
    EXPECT_FALSE(ScopeMatcher::matches("messages:*", "files:read"));
    EXPECT_FALSE(ScopeMatcher::matches("messages:*", "auth:revoke"));

    // Prefixes that don't match domain delimiter
    EXPECT_FALSE(ScopeMatcher::matches("messages:*", "messages_extra:read"));
    EXPECT_FALSE(ScopeMatcher::matches("messages:*", "messages"));

    // Empty action following domain delimiter
    EXPECT_FALSE(ScopeMatcher::matches("messages:*", "messages:"));
}

TEST(ScopeMatcherTest, MalformedAndEmptyScopesSafelyRejected) {
    EXPECT_FALSE(ScopeMatcher::matches("", "messages:read"));
    EXPECT_FALSE(ScopeMatcher::matches("messages:read", ""));
    EXPECT_FALSE(ScopeMatcher::matches("", ""));

    // Wildcard without domain
    EXPECT_FALSE(ScopeMatcher::matches(":*", "messages:read"));

    // Embedded wildcards in domain
    EXPECT_FALSE(ScopeMatcher::matches("*:*", "messages:read"));
    EXPECT_FALSE(ScopeMatcher::matches("mess*ges:*", "messages:read"));
}

TEST(ScopeMatcherTest, CaseSensitivityStrictlyEnforced) {
    EXPECT_FALSE(ScopeMatcher::matches("Messages:*", "messages:read"));
    EXPECT_FALSE(ScopeMatcher::matches("messages:*", "MESSAGES:read"));
    EXPECT_FALSE(ScopeMatcher::matches("messages:READ", "messages:read"));
    EXPECT_FALSE(ScopeMatcher::matches("messages:read", "messages:READ"));
}

TEST(ScopeMatcherTest, HasScopeEvaluatesCollection) {
    const std::vector<std::string> granted = {"messages:read", "files:*"};

    EXPECT_TRUE(ScopeMatcher::has_scope(granted, "messages:read"));
    EXPECT_FALSE(ScopeMatcher::has_scope(granted, "messages:write"));
    EXPECT_TRUE(ScopeMatcher::has_scope(granted, "files:upload"));
    EXPECT_TRUE(ScopeMatcher::has_scope(granted, "files:download"));
    EXPECT_FALSE(ScopeMatcher::has_scope(granted, "auth:revoke"));
    EXPECT_FALSE(ScopeMatcher::has_scope(granted, ""));

    const std::vector<std::string> empty_granted;
    EXPECT_FALSE(ScopeMatcher::has_scope(empty_granted, "messages:read"));
}

TEST(ScopeMatcherTest, HasAllScopesEvaluatesConjunction) {
    const std::vector<std::string> granted = {"messages:*", "files:read"};

    // Both satisfied (messages:read via wildcard, files:read via exact)
    EXPECT_TRUE(ScopeMatcher::has_all_scopes(granted, {"messages:read", "files:read"}));
    EXPECT_TRUE(ScopeMatcher::has_all_scopes(granted, {"messages:send"}));

    // Missing files:write
    EXPECT_FALSE(ScopeMatcher::has_all_scopes(granted, {"messages:read", "files:write"}));

    // Empty required scopes is vacuously true
    EXPECT_TRUE(ScopeMatcher::has_all_scopes(granted, {}));

    const std::vector<std::string> empty_granted;
    EXPECT_TRUE(ScopeMatcher::has_all_scopes(empty_granted, {}));
    EXPECT_FALSE(ScopeMatcher::has_all_scopes(empty_granted, {"messages:read"}));
}

TEST(ScopeMatcherTest, HasAnyScopeEvaluatesDisjunction) {
    const std::vector<std::string> granted = {"messages:read"};

    // At least one alternative satisfied
    EXPECT_TRUE(ScopeMatcher::has_any_scope(granted, {"messages:read", "messages:write"}));
    EXPECT_TRUE(ScopeMatcher::has_any_scope(granted, {"files:read", "messages:read"}));

    // None satisfied
    EXPECT_FALSE(ScopeMatcher::has_any_scope(granted, {"messages:write", "files:read"}));

    // Empty alternative scopes is vacuously true
    EXPECT_TRUE(ScopeMatcher::has_any_scope(granted, {}));

    const std::vector<std::string> empty_granted;
    EXPECT_TRUE(ScopeMatcher::has_any_scope(empty_granted, {}));
    EXPECT_FALSE(ScopeMatcher::has_any_scope(empty_granted, {"messages:read"}));
}

TEST(ScopeMatcherTest, FindMissingScopesReportsUnsatisfiedRequirements) {
    const std::vector<std::string> granted = {"messages:*", "auth:profile"};
    const std::vector<std::string> required = {"messages:send", "files:upload", "audit:read"};

    const auto missing = ScopeMatcher::find_missing_scopes(granted, required);
    ASSERT_EQ(missing.size(), 2u);
    EXPECT_EQ(missing[0], "files:upload");
    EXPECT_EQ(missing[1], "audit:read");

    const auto none_missing = ScopeMatcher::find_missing_scopes(granted, {"messages:read", "auth:profile"});
    EXPECT_TRUE(none_missing.empty());
}

TEST(ScopeMatcherTest, AuthenticatedContextIntegratesWithScopeMatcher) {
    AuthenticatedContext ctx("usr_123", "dev_456", "ses_789",
                             securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
                             {"messages:*", "auth:profile"}, 2000000000000LL);

    // Exact match from context
    EXPECT_TRUE(ctx.has_scope("auth:profile"));

    // Domain wildcard matches actions under messages:
    EXPECT_TRUE(ctx.has_scope("messages:read"));
    EXPECT_TRUE(ctx.has_scope("messages:send"));
    EXPECT_TRUE(ctx.has_scope("messages:delete"));

    // Non-granted scopes
    EXPECT_FALSE(ctx.has_scope("files:upload"));
    EXPECT_FALSE(ctx.has_scope("auth:device:register"));
}

} // namespace
} // namespace securecloud::gateway::http
