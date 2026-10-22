#include "domain/producer_identity_validator.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::domain::test {

    TEST(ProducerIdentityValidatorTest, MatchingSanAuthorizesProducer) {
        PeerIdentity peer;
        peer.is_authenticated = true;
        peer.common_name = "auth.securecloud.internal";

        auto res = ProducerIdentityValidator::validate_producer_authorization(ProducerService::Auth, peer);
        EXPECT_TRUE(res.is_valid());
    }

    TEST(ProducerIdentityValidatorTest, MismatchedSanRejected) {
        PeerIdentity peer;
        peer.is_authenticated = true;
        peer.common_name = "messaging.securecloud.internal";

        auto res = ProducerIdentityValidator::validate_producer_authorization(ProducerService::Files, peer);
        EXPECT_FALSE(res.is_valid());
        ASSERT_FALSE(res.errors().empty());
        EXPECT_EQ(res.errors()[0].code, AuditValidationErrorCode::UnauthorizedProducer);
    }

    TEST(ProducerIdentityValidatorTest, UnauthenticatedPeerRejected) {
        PeerIdentity peer;
        peer.is_authenticated = false;
        peer.common_name = "auth.securecloud.internal";

        auto res = ProducerIdentityValidator::validate_producer_authorization(ProducerService::Auth, peer);
        EXPECT_FALSE(res.is_valid());
    }

    TEST(ProducerIdentityValidatorTest, InternalAuditProducerStrictlyGated) {
        PeerIdentity peer;
        peer.is_authenticated = true;
        peer.common_name = "gateway.securecloud.internal";

        // Gateway claiming to produce internal Audit events -> Rejected
        auto res = ProducerIdentityValidator::validate_producer_authorization(ProducerService::Audit, peer);
        EXPECT_FALSE(res.is_valid());
    }

} // namespace securecloud::audit::domain::test