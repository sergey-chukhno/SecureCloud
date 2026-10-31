#include "query/audit_query_authorizer.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::query::testing {

class AuditQueryAuthorizerTest : public ::testing::Test {
  protected:
    domain::PeerIdentity build_peer(std::string_view cn, bool authenticated = true) {
        domain::PeerIdentity peer;
        peer.is_authenticated = authenticated;
        peer.common_name = std::string(cn);
        peer.san_dns_names.push_back(std::string(cn));
        return peer;
    }
};

TEST_F(AuditQueryAuthorizerTest, AuditInternalIdentityPermittedGlobalQueries) {
    auto peer = build_peer("audit.securecloud.internal");
    AuditQueryFilter filter; // Global search across all producers

    auto status = AuditQueryAuthorizer::authorize_query(peer, filter);

    EXPECT_TRUE(status.ok());
}

TEST_F(AuditQueryAuthorizerTest, RuntimeProducerPermittedSelfScopeOnly) {
    auto peer = build_peer("auth.securecloud.internal");

    // 1. Allowed self-scoped search
    AuditQueryFilter self_filter;
    self_filter.producer_services = {domain::ProducerService::Auth};
    auto status_self = AuditQueryAuthorizer::authorize_query(peer, self_filter);
    EXPECT_TRUE(status_self.ok());

    // 2. Denied cross-service search
    AuditQueryFilter cross_filter;
    cross_filter.producer_services = {domain::ProducerService::Messaging};
    auto status_cross = AuditQueryAuthorizer::authorize_query(peer, cross_filter);
    EXPECT_EQ(status_cross.error_code(), grpc::StatusCode::PERMISSION_DENIED);

    // 3. Denied global search (omitted producer_services filter)
    AuditQueryFilter global_filter;
    auto status_global = AuditQueryAuthorizer::authorize_query(peer, global_filter);
    EXPECT_EQ(status_global.error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

TEST_F(AuditQueryAuthorizerTest, GatewayCallerBlockedFromGlobalOperatorQueriesByDefault) {
    auto peer = build_peer("gateway.securecloud.internal");
    AuditQueryFilter filter; // Global operator investigation

    auto status = AuditQueryAuthorizer::authorize_query(peer, filter);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

TEST_F(AuditQueryAuthorizerTest, UnauthenticatedCallerRejected) {
    auto peer = build_peer("audit.securecloud.internal", false); // Unauthenticated peer
    AuditQueryFilter filter;

    auto status = AuditQueryAuthorizer::authorize_query(peer, filter);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
}

} // namespace securecloud::audit::query::testing