#include "securecloud/auth/v1/auth.grpc.pb.h"
#include "securecloud/auth/v1/auth.pb.h"
#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/common/v1/health.pb.h"
#include "securecloud/files/v1/files.grpc.pb.h"
#include "securecloud/files/v1/files.pb.h"

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

namespace {
constexpr uint64_t k_test_encrypted_size = 10485760;
constexpr uint32_t k_test_expected_chunks = 3;
} // namespace

TEST(ProtoSmokeTest, FilesMessageConstructionAndSerialization) {
    securecloud::files::v1::CreateFileUploadRequest request;
    request.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    request.set_owner_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    request.set_owner_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    request.set_encrypted_size_bytes(k_test_encrypted_size);
    request.set_expected_chunk_count(k_test_expected_chunks);
    request.set_encryption_version("v1-xchacha20poly1305");

    EXPECT_EQ(request.file_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    EXPECT_EQ(request.expected_chunk_count(), k_test_expected_chunks);

    std::string serialized;
    ASSERT_TRUE(request.SerializeToString(&serialized));
    EXPECT_FALSE(serialized.empty());

    securecloud::files::v1::CreateFileUploadRequest restored;
    ASSERT_TRUE(restored.ParseFromString(serialized));
    EXPECT_EQ(restored.file_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    EXPECT_EQ(restored.expected_chunk_count(), k_test_expected_chunks);
    EXPECT_EQ(restored.encryption_version(), "v1-xchacha20poly1305");

    securecloud::files::v1::CreateFileUploadResponse response;
    response.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003");
    response.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    response.set_status(securecloud::files::v1::TRANSFER_STATUS_PENDING);
    EXPECT_EQ(response.status(), securecloud::files::v1::TRANSFER_STATUS_PENDING);

    securecloud::files::v1::GetFileMetadataResponse meta_response;
    meta_response.set_lifecycle_state(securecloud::files::v1::FILE_LIFECYCLE_STATE_AVAILABLE);
    EXPECT_EQ(meta_response.lifecycle_state(), securecloud::files::v1::FILE_LIFECYCLE_STATE_AVAILABLE);
}

TEST(ProtoSmokeTest, FilesServiceStubTypeLinkage) {
    EXPECT_TRUE(
        (std::is_same_v<securecloud::files::v1::FilesService::Service, securecloud::files::v1::FilesService::Service>));
    EXPECT_TRUE(
        (std::is_same_v<securecloud::files::v1::FilesService::Stub, securecloud::files::v1::FilesService::Stub>));
}
