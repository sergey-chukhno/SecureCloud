#include "securecloud/auth/v1/auth.grpc.pb.h"
#include "securecloud/auth/v1/auth.pb.h"
#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/common/v1/health.pb.h"
#include "securecloud/files/v1/files.grpc.pb.h"
#include "securecloud/files/v1/files.pb.h"
#include "securecloud/messaging/v1/messaging.grpc.pb.h"
#include "securecloud/messaging/v1/messaging.pb.h"

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

TEST(ProtoSmokeTest, MessagingMessageConstructionAndSerialization) {
    securecloud::messaging::v1::SendMessageRequest request;
    request.set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36010");
    request.set_sender_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36011");
    request.set_priority(securecloud::messaging::v1::MESSAGE_PRIORITY_URGENT);
    request.set_client_idempotency_token("idem-token-12345");
    request.set_expires_at_unix_ms(1760000000000LL);

    auto* target = request.add_delivery_targets();
    target->set_recipient_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36012");
    target->set_recipient_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36013");
    target->set_state(securecloud::messaging::v1::DELIVERY_STATE_QUEUED);

    auto* payload = target->mutable_encrypted_payload();
    payload->set_ciphertext_blob("test_ciphertext_blob");
    payload->set_ephemeral_public_key("test_ephemeral_key");
    payload->set_initialization_vector("test_iv_12bytes");
    payload->set_auth_tag("test_auth_tag16b");
    payload->set_algorithm("AES-256-GCM");

    EXPECT_EQ(request.conversation_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36010");
    EXPECT_EQ(request.priority(), securecloud::messaging::v1::MESSAGE_PRIORITY_URGENT);
    EXPECT_EQ(request.delivery_targets_size(), 1);

    std::string serialized;
    ASSERT_TRUE(request.SerializeToString(&serialized));
    EXPECT_FALSE(serialized.empty());

    securecloud::messaging::v1::SendMessageRequest restored;
    ASSERT_TRUE(restored.ParseFromString(serialized));
    EXPECT_EQ(restored.conversation_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36010");
    EXPECT_EQ(restored.priority(), securecloud::messaging::v1::MESSAGE_PRIORITY_URGENT);
    ASSERT_EQ(restored.delivery_targets_size(), 1);
    EXPECT_EQ(restored.delivery_targets(0).recipient_device_id(), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36013");
    EXPECT_EQ(restored.delivery_targets(0).encrypted_payload().ciphertext_blob(), "test_ciphertext_blob");

    securecloud::messaging::v1::SendMessageResponse response;
    response.set_message_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36099");
    response.set_conversation_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36010");
    response.set_accepted_at_unix_ms(1750000000000LL);
    response.set_initial_state(securecloud::messaging::v1::DELIVERY_STATE_QUEUED);
    response.set_target_count(1);
    EXPECT_EQ(response.initial_state(), securecloud::messaging::v1::DELIVERY_STATE_QUEUED);
}

TEST(ProtoSmokeTest, MessagingServiceStubTypeLinkage) {
    EXPECT_TRUE((std::is_same_v<securecloud::messaging::v1::MessagingService::Service,
                                securecloud::messaging::v1::MessagingService::Service>));
    EXPECT_TRUE((std::is_same_v<securecloud::messaging::v1::MessagingService::Stub,
                                securecloud::messaging::v1::MessagingService::Stub>));
}
