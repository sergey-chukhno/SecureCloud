#include "security/producer_identity_validator.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::security::testing {

    TEST(ProducerIdentityValidatorTest, RejectUnauthenticatedContext) {
        grpc::ServerContext unauthenticated_ctx{};
        auto status = ProducerIdentityValidator::validate_peer_context(
            unauthenticated_ctx, domain::ProducerService::Auth);

        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
        EXPECT_NE(status.error_message().find("Authentication required"), std::string::npos);
    }

    TEST(ProducerIdentityValidatorTest, RejectInvalidProducerString) {
        grpc::ServerContext ctx{};
        auto status = ProducerIdentityValidator::validate_peer_context(
            ctx, "invalid_producer_service");

        EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
    }

} // namespace securecloud::audit::security::testing