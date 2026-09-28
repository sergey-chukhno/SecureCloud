#include "http/auth/request_context.hpp"

#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace securecloud::gateway::http {
namespace {

AuthenticatedContext make_sample_auth_context() {
    return AuthenticatedContext("usr-test-456", "dev-test-789", "sess-test-999",
                                securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED,
                                {"messages:write", "files:read"}, 1700000000000);
}

TEST(RequestContextTest, BindsAndRetrievesRequestContextInScope) {
    EXPECT_EQ(RequestContext::current(), nullptr);

    RequestContext ctx("req-123", "192.168.1.50", 1700000000123, make_sample_auth_context());
    {
        ScopedRequestContext scoped(ctx);
        const auto* current = RequestContext::current();
        ASSERT_NE(current, nullptr);
        EXPECT_EQ(current->request_id(), "req-123");
        EXPECT_EQ(current->client_ip(), "192.168.1.50");
        EXPECT_EQ(current->request_timestamp_ms(), 1700000000123);
        EXPECT_TRUE(current->is_authenticated());
        ASSERT_TRUE(current->authenticated_context().has_value());
        EXPECT_EQ(current->authenticated_context()->user_id(), "usr-test-456");
        EXPECT_EQ(current->authenticated_context()->device_id(), "dev-test-789");
    }

    EXPECT_EQ(RequestContext::current(), nullptr);
}

TEST(RequestContextTest, CleansUpOnNormalScopeExit) {
    EXPECT_EQ(RequestContext::current(), nullptr);

    {
        RequestContext ctx("req-scope-1", "127.0.0.1", 1000);
        ScopedRequestContext scoped(ctx);
        EXPECT_NE(RequestContext::current(), nullptr);
    }

    EXPECT_EQ(RequestContext::current(), nullptr);
}

TEST(RequestContextTest, CleansUpOnExceptionUnwind) {
    EXPECT_EQ(RequestContext::current(), nullptr);

    EXPECT_THROW(
        {
            RequestContext ctx("req-throw-1", "10.0.0.1", 2000);
            ScopedRequestContext scoped(ctx);
            EXPECT_NE(RequestContext::current(), nullptr);
            throw std::runtime_error("Simulated handler crash during request execution");
        },
        std::runtime_error);

    // RAII must have deterministically restored/cleared context during stack unwinding
    EXPECT_EQ(RequestContext::current(), nullptr);
}

TEST(RequestContextTest, SupportsNestedScopesDeterministically) {
    EXPECT_EQ(RequestContext::current(), nullptr);

    RequestContext outer_ctx("req-outer", "10.0.0.1", 1000);
    RequestContext inner_ctx("req-inner", "10.0.0.2", 2000, make_sample_auth_context());

    {
        ScopedRequestContext outer_scope(outer_ctx);
        EXPECT_EQ(RequestContext::current()->request_id(), "req-outer");
        EXPECT_FALSE(RequestContext::current()->is_authenticated());

        {
            ScopedRequestContext inner_scope(inner_ctx);
            EXPECT_EQ(RequestContext::current()->request_id(), "req-inner");
            EXPECT_TRUE(RequestContext::current()->is_authenticated());
        }

        // Restored to outer context
        EXPECT_EQ(RequestContext::current()->request_id(), "req-outer");
        EXPECT_FALSE(RequestContext::current()->is_authenticated());
    }

    // Fully cleared
    EXPECT_EQ(RequestContext::current(), nullptr);
}

TEST(RequestContextTest, UnauthenticatedContextReportsAccurately) {
    RequestContext ctx("req-unauth", "127.0.0.1", 5000, std::nullopt);
    ScopedRequestContext scoped(ctx);

    const auto* current = RequestContext::current();
    ASSERT_NE(current, nullptr);
    EXPECT_EQ(current->request_id(), "req-unauth");
    EXPECT_FALSE(current->is_authenticated());
    EXPECT_FALSE(current->authenticated_context().has_value());
}

} // namespace
} // namespace securecloud::gateway::http
