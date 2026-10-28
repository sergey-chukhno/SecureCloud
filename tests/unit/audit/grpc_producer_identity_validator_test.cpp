#include "security/grpc_producer_identity_validator.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::security::testing {

    TEST(GrpcProducerIdentityValidatorTest, RejectUnauthenticatedContext) {
        grpc::ServerContext unauthenticated_ctx{};
        auto status =
            GrpcProducerIdentityValidator::validate_peer_context(unauthenticated_ctx, domain::ProducerService::Auth);

        EXPECT_TRUE(status.ok());
    }

    TEST(GrpcProducerIdentityValidatorTest, RejectInvalidProducerString) {
        grpc::ServerContext ctx{};
        auto status = GrpcProducerIdentityValidator::validate_peer_context(ctx, "invalid_producer_service");

        EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
    }

} // namespace securecloud::audit::security::testing