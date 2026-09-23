#include "securecloud/auth/v1/auth.grpc.pb.h"
#include "securecloud/auth/v1/auth.pb.h"
#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/common/v1/health.pb.h"

#include <gtest/gtest.h>
#include <string>

TEST(ProtoSmokeTest, MessageConstructionAndSerialization) {
    securecloud::common::v1::HealthCheckRequest request;
    request.set_service("auth");
    EXPECT_EQ(request.service(), "auth");

    securecloud::common::v1::HealthCheckResponse response;
    response.set_status(securecloud::common::v1::HealthCheckResponse::SERVING);
    EXPECT_EQ(response.status(), securecloud::common::v1::HealthCheckResponse::SERVING);

    std::string serialized;
    ASSERT_TRUE(request.SerializeToString(&serialized));
    EXPECT_FALSE(serialized.empty());

    securecloud::common::v1::HealthCheckRequest restored;
    ASSERT_TRUE(restored.ParseFromString(serialized));
    EXPECT_EQ(restored.service(), "auth");
}

TEST(ProtoSmokeTest, ServiceStubTypeLinkage) {
    // Verify gRPC service interface and stub types compile and link successfully
    EXPECT_TRUE((std::is_same_v<securecloud::common::v1::HealthService::Service,
                                securecloud::common::v1::HealthService::Service>));
    EXPECT_TRUE(
        (std::is_same_v<securecloud::common::v1::HealthService::Stub, securecloud::common::v1::HealthService::Stub>));
}

TEST(ProtoSmokeTest, AuthMessageConstructionAndSerialization) {
    securecloud::auth::v1::AuthenticateRequest request;
    request.set_credential_identifier("alice@example.com");
    request.set_password("secure_password");
    request.set_device_id("00000000-0000-0000-0000-000000000001");

    EXPECT_EQ(request.credential_identifier(), "alice@example.com");
    EXPECT_EQ(request.password(), "secure_password");
    EXPECT_EQ(request.device_id(), "00000000-0000-0000-0000-000000000001");

    std::string serialized;
    ASSERT_TRUE(request.SerializeToString(&serialized));
    EXPECT_FALSE(serialized.empty());

    securecloud::auth::v1::AuthenticateRequest restored;
    ASSERT_TRUE(restored.ParseFromString(serialized));
    EXPECT_EQ(restored.credential_identifier(), "alice@example.com");
}

TEST(ProtoSmokeTest, AuthServiceStubTypeLinkage) {
    // Verify Auth gRPC service interface and stub types compile and link successfully
    EXPECT_TRUE(
        (std::is_same_v<securecloud::auth::v1::AuthService::Service, securecloud::auth::v1::AuthService::Service>));
    EXPECT_TRUE((std::is_same_v<securecloud::auth::v1::AuthService::Stub, securecloud::auth::v1::AuthService::Stub>));
}
