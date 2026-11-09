// Compile-guard test (§4.5): Verifies gateway_audit_producer.hpp can be safely included
// alongside Auth headers without triggering ODR or symbol include collisions.
#include "audit/gateway_audit_producer.hpp"

// Intentionally include Auth and Gateway HTTP headers to verify include-path isolation
#include "http/auth/authenticated_context.hpp"
#include "securecloud/auth/v1/auth.pb.h"

#include <gtest/gtest.h>

TEST(HeaderCollisionTest, CompilesWithoutSymbolOrIncludeConflict) {
    securecloud::gateway::audit::GatewayAuditObservation obs;
    obs.type = securecloud::gateway::audit::GatewayAuditEventType::TokenRejected;

    EXPECT_EQ(obs.target_id, "gateway");
}
