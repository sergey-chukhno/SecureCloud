#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/service/auth_service_impl.hpp"
#include "auth/service/prekey_manager.hpp"
#include "securecloud/auth/v1/auth.grpc.pb.h"

#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace securecloud::auth::service::test {
namespace {

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;

using domain::PrekeyExhaustionState;
using domain::PrekeyInventoryStatus;
using domain::Uuid;

// ============================================================================
// Mocks
// ============================================================================

class MockPrekeyManager : public IPrekeyManager {
  public:
    MOCK_METHOD(PrekeyInventoryStatusResult, get_inventory_status, (const Uuid& device_id), (override));
    MOCK_METHOD(ClaimPrekeyBundleResult, claim_device_prekey_bundle, (const Uuid& device_id), (override));

    MOCK_METHOD(ReplenishPrekeysResult, replenish_one_time_prekeys,
                (const Uuid& caller_user_id, const Uuid& caller_device_id, const domain::Uuid& target_device_id,
                 const std::vector<std::vector<uint8_t>>& new_otks, std::string_view client_ip),
                (override));

    RotateSignedPrekeyResult rotate_signed_prekey(const Uuid& caller_user_id, const Uuid& caller_device_id,
                                                  const Uuid& target_device_id,
                                                  std::span<const uint8_t> new_signed_prekey,
                                                  std::span<const uint8_t> new_signature,
                                                  std::string_view client_ip) override {
        return rotate_signed_prekey_impl(caller_user_id, caller_device_id, target_device_id,
                                         std::vector<uint8_t>(new_signed_prekey.begin(), new_signed_prekey.end()),
                                         std::vector<uint8_t>(new_signature.begin(), new_signature.end()),
                                         std::string(client_ip));
    }

    MOCK_METHOD(RotateSignedPrekeyResult, rotate_signed_prekey_impl,
                (const Uuid&, const Uuid&, const Uuid&, const std::vector<uint8_t>&, const std::vector<uint8_t>&,
                 const std::string&));
};

// ============================================================================
// Test Fixture
// ============================================================================

class AuthServicePrekeyTest : public ::testing::Test {
  protected:
    void SetUp() override {
        mock_prekey_mgr_ = std::make_shared<NiceMock<MockPrekeyManager>>();

        auth_service_ = std::make_unique<AuthServiceImpl>(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                                                          mock_prekey_mgr_);

        device_id_ = Uuid::generate_v7();
    }

    std::shared_ptr<NiceMock<MockPrekeyManager>> mock_prekey_mgr_;
    std::unique_ptr<AuthServiceImpl> auth_service_;
    Uuid device_id_;
    grpc::ServerContext context_;
};

// ============================================================================
// GetPrekeyInventoryStatus Tests
// ============================================================================

TEST_F(AuthServicePrekeyTest, GetPrekeyInventoryStatus_UnconfiguredManager_ReturnsUnimplemented) {
    AuthServiceImpl unconfigured_service;
    securecloud::auth::v1::GetPrekeyInventoryStatusRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::GetPrekeyInventoryStatusResponse resp;

    auto status = unconfigured_service.GetPrekeyInventoryStatus(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
}

TEST_F(AuthServicePrekeyTest, GetPrekeyInventoryStatus_NullRequestOrResponse_ReturnsInvalidArgument) {
    securecloud::auth::v1::GetPrekeyInventoryStatusRequest req;
    securecloud::auth::v1::GetPrekeyInventoryStatusResponse resp;

    auto s1 = auth_service_->GetPrekeyInventoryStatus(&context_, nullptr, &resp);
    EXPECT_EQ(s1.error_code(), grpc::StatusCode::INVALID_ARGUMENT);

    auto s2 = auth_service_->GetPrekeyInventoryStatus(&context_, &req, nullptr);
    EXPECT_EQ(s2.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST_F(AuthServicePrekeyTest, GetPrekeyInventoryStatus_MalformedDeviceId_ReturnsInvalidArgument) {
    securecloud::auth::v1::GetPrekeyInventoryStatusRequest req;
    req.set_device_id("not-a-valid-uuid");
    securecloud::auth::v1::GetPrekeyInventoryStatusResponse resp;

    auto status = auth_service_->GetPrekeyInventoryStatus(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST_F(AuthServicePrekeyTest, GetPrekeyInventoryStatus_Success_ReturnsValidResponseWithMetrics) {
    auto now = std::chrono::system_clock::now();
    PrekeyInventoryStatus inv{
        .device_id = device_id_,
        .active_one_time_prekeys = 45,
        .claimed_one_time_prekeys = 15,
        .low_inventory_threshold = 20,
        .is_low_inventory = false,
        .is_exhausted = false,
        .signed_prekey_created_at = now,
        .signed_prekey_age_seconds = 120,
        .signed_prekey_needs_rotation = false,
    };

    EXPECT_CALL(*mock_prekey_mgr_, get_inventory_status(device_id_))
        .WillOnce(Return(PrekeyInventoryStatusResult::success(inv)));

    securecloud::auth::v1::GetPrekeyInventoryStatusRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::GetPrekeyInventoryStatusResponse resp;

    auto status = auth_service_->GetPrekeyInventoryStatus(&context_, &req, &resp);
    ASSERT_TRUE(status.ok());
    EXPECT_EQ(resp.device_id(), device_id_.to_string());
    EXPECT_EQ(resp.active_one_time_prekeys(), 45);
    EXPECT_EQ(resp.claimed_one_time_prekeys(), 15);
    EXPECT_EQ(resp.low_inventory_threshold(), 20);
    EXPECT_FALSE(resp.is_low_inventory());
    EXPECT_FALSE(resp.is_exhausted());
    EXPECT_EQ(resp.signed_prekey_age_seconds(), 120);
    EXPECT_FALSE(resp.signed_prekey_needs_rotation());
    EXPECT_GT(resp.signed_prekey_created_at_epoch_ms(), 0);
}

TEST_F(AuthServicePrekeyTest, GetPrekeyInventoryStatus_NotFound_ReturnsNotFound) {
    EXPECT_CALL(*mock_prekey_mgr_, get_inventory_status(device_id_))
        .WillOnce(Return(PrekeyInventoryStatusResult::not_found("Target device not found")));

    securecloud::auth::v1::GetPrekeyInventoryStatusRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::GetPrekeyInventoryStatusResponse resp;

    auto status = auth_service_->GetPrekeyInventoryStatus(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::NOT_FOUND);
}

TEST_F(AuthServicePrekeyTest, GetPrekeyInventoryStatus_DeviceRevoked_ReturnsPermissionDenied) {
    EXPECT_CALL(*mock_prekey_mgr_, get_inventory_status(device_id_))
        .WillOnce(Return(PrekeyInventoryStatusResult::device_revoked("Device is revoked")));

    securecloud::auth::v1::GetPrekeyInventoryStatusRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::GetPrekeyInventoryStatusResponse resp;

    auto status = auth_service_->GetPrekeyInventoryStatus(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

TEST_F(AuthServicePrekeyTest, GetPrekeyInventoryStatus_InternalError_ReturnsInternal) {
    EXPECT_CALL(*mock_prekey_mgr_, get_inventory_status(device_id_))
        .WillOnce(Return(PrekeyInventoryStatusResult::internal_error("Database failure")));

    securecloud::auth::v1::GetPrekeyInventoryStatusRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::GetPrekeyInventoryStatusResponse resp;

    auto status = auth_service_->GetPrekeyInventoryStatus(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INTERNAL);
}

// ============================================================================
// ClaimPrekeyBundle Tests
// ============================================================================

TEST_F(AuthServicePrekeyTest, ClaimPrekeyBundle_UnconfiguredManager_ReturnsUnimplemented) {
    AuthServiceImpl unconfigured_service;
    securecloud::auth::v1::ClaimPrekeyBundleRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::ClaimPrekeyBundleResponse resp;

    auto status = unconfigured_service.ClaimPrekeyBundle(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
}

TEST_F(AuthServicePrekeyTest, ClaimPrekeyBundle_NullRequestOrResponse_ReturnsInvalidArgument) {
    securecloud::auth::v1::ClaimPrekeyBundleRequest req;
    securecloud::auth::v1::ClaimPrekeyBundleResponse resp;

    auto s1 = auth_service_->ClaimPrekeyBundle(&context_, nullptr, &resp);
    EXPECT_EQ(s1.error_code(), grpc::StatusCode::INVALID_ARGUMENT);

    auto s2 = auth_service_->ClaimPrekeyBundle(&context_, &req, nullptr);
    EXPECT_EQ(s2.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST_F(AuthServicePrekeyTest, ClaimPrekeyBundle_MalformedDeviceId_ReturnsInvalidArgument) {
    securecloud::auth::v1::ClaimPrekeyBundleRequest req;
    req.set_device_id("invalid-uuid");
    securecloud::auth::v1::ClaimPrekeyBundleResponse resp;

    auto status = auth_service_->ClaimPrekeyBundle(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST_F(AuthServicePrekeyTest, ClaimPrekeyBundle_SuccessHealthy_ReturnsBundleAndHealthyEnum) {
    std::vector<uint8_t> id_key(32, 0x11);
    std::string fingerprint = "a1b2c3d4";
    std::vector<uint8_t> spk(32, 0x22);
    std::vector<uint8_t> sig(64, 0x33);
    auto now = std::chrono::system_clock::now();
    std::vector<uint8_t> otk(32, 0x44);
    auto otk_id = Uuid::generate_v7();

    auto claim_res = ClaimPrekeyBundleResult::success(device_id_, id_key, fingerprint, spk, sig, now, otk, otk_id,
                                                      PrekeyExhaustionState::InventoryHealthy);

    EXPECT_CALL(*mock_prekey_mgr_, claim_device_prekey_bundle(device_id_)).WillOnce(Return(claim_res));

    securecloud::auth::v1::ClaimPrekeyBundleRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::ClaimPrekeyBundleResponse resp;

    auto status = auth_service_->ClaimPrekeyBundle(&context_, &req, &resp);
    ASSERT_TRUE(status.ok());
    EXPECT_EQ(resp.exhaustion_state(), securecloud::auth::v1::PREKEY_EXHAUSTION_STATE_HEALTHY);
    EXPECT_EQ(resp.bundle().device_id(), device_id_.to_string());
    EXPECT_EQ(resp.bundle().identity_key(), std::string(id_key.begin(), id_key.end()));
    EXPECT_EQ(resp.bundle().identity_key_fingerprint(), fingerprint);
    EXPECT_EQ(resp.bundle().signed_prekey(), std::string(spk.begin(), spk.end()));
    EXPECT_EQ(resp.bundle().signed_prekey_signature(), std::string(sig.begin(), sig.end()));
    EXPECT_EQ(resp.bundle().one_time_prekey(), std::string(otk.begin(), otk.end()));
    EXPECT_EQ(resp.bundle().one_time_prekey_id(), otk_id.to_string());
    EXPECT_EQ(resp.bundle().status(), securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
}

TEST_F(AuthServicePrekeyTest, ClaimPrekeyBundle_SuccessLowInventory_ReturnsBundleAndLowEnum) {
    std::vector<uint8_t> id_key(32, 0x11);
    std::string fingerprint = "a1b2c3d4";
    std::vector<uint8_t> spk(32, 0x22);
    std::vector<uint8_t> sig(64, 0x33);
    auto now = std::chrono::system_clock::now();
    std::vector<uint8_t> otk(32, 0x44);
    auto otk_id = Uuid::generate_v7();

    auto claim_res = ClaimPrekeyBundleResult::success(device_id_, id_key, fingerprint, spk, sig, now, otk, otk_id,
                                                      PrekeyExhaustionState::InventoryLow);

    EXPECT_CALL(*mock_prekey_mgr_, claim_device_prekey_bundle(device_id_)).WillOnce(Return(claim_res));

    securecloud::auth::v1::ClaimPrekeyBundleRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::ClaimPrekeyBundleResponse resp;

    auto status = auth_service_->ClaimPrekeyBundle(&context_, &req, &resp);
    ASSERT_TRUE(status.ok());
    EXPECT_EQ(resp.exhaustion_state(), securecloud::auth::v1::PREKEY_EXHAUSTION_STATE_LOW);
}

TEST_F(AuthServicePrekeyTest, ClaimPrekeyBundle_SuccessExhausted_ReturnsBundleAndExhaustedEnum) {
    std::vector<uint8_t> id_key(32, 0x11);
    std::string fingerprint = "a1b2c3d4";
    std::vector<uint8_t> spk(32, 0x22);
    std::vector<uint8_t> sig(64, 0x33);
    auto now = std::chrono::system_clock::now();

    auto claim_res = ClaimPrekeyBundleResult::success(device_id_, id_key, fingerprint, spk, sig, now, std::nullopt,
                                                      std::nullopt, PrekeyExhaustionState::InventoryExhausted);

    EXPECT_CALL(*mock_prekey_mgr_, claim_device_prekey_bundle(device_id_)).WillOnce(Return(claim_res));

    securecloud::auth::v1::ClaimPrekeyBundleRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::ClaimPrekeyBundleResponse resp;

    auto status = auth_service_->ClaimPrekeyBundle(&context_, &req, &resp);
    ASSERT_TRUE(status.ok());
    EXPECT_EQ(resp.exhaustion_state(), securecloud::auth::v1::PREKEY_EXHAUSTION_STATE_EXHAUSTED);
    EXPECT_TRUE(resp.bundle().one_time_prekey().empty());
}

TEST_F(AuthServicePrekeyTest, ClaimPrekeyBundle_NotFound_ReturnsNotFound) {
    EXPECT_CALL(*mock_prekey_mgr_, claim_device_prekey_bundle(device_id_))
        .WillOnce(Return(ClaimPrekeyBundleResult::not_found("Target device not found")));

    securecloud::auth::v1::ClaimPrekeyBundleRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::ClaimPrekeyBundleResponse resp;

    auto status = auth_service_->ClaimPrekeyBundle(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::NOT_FOUND);
}

TEST_F(AuthServicePrekeyTest, ClaimPrekeyBundle_DeviceRevoked_ReturnsPermissionDenied) {
    EXPECT_CALL(*mock_prekey_mgr_, claim_device_prekey_bundle(device_id_))
        .WillOnce(Return(ClaimPrekeyBundleResult::device_revoked("Device is revoked")));

    securecloud::auth::v1::ClaimPrekeyBundleRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::ClaimPrekeyBundleResponse resp;

    auto status = auth_service_->ClaimPrekeyBundle(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

TEST_F(AuthServicePrekeyTest, ClaimPrekeyBundle_DeviceNotActive_ReturnsFailedPrecondition) {
    EXPECT_CALL(*mock_prekey_mgr_, claim_device_prekey_bundle(device_id_))
        .WillOnce(Return(ClaimPrekeyBundleResult::device_not_active("Device is not active")));

    securecloud::auth::v1::ClaimPrekeyBundleRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::ClaimPrekeyBundleResponse resp;

    auto status = auth_service_->ClaimPrekeyBundle(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::FAILED_PRECONDITION);
}

TEST_F(AuthServicePrekeyTest, ClaimPrekeyBundle_InternalError_ReturnsInternal) {
    EXPECT_CALL(*mock_prekey_mgr_, claim_device_prekey_bundle(device_id_))
        .WillOnce(Return(ClaimPrekeyBundleResult::internal_error("Repository failure")));

    securecloud::auth::v1::ClaimPrekeyBundleRequest req;
    req.set_device_id(device_id_.to_string());
    securecloud::auth::v1::ClaimPrekeyBundleResponse resp;

    auto status = auth_service_->ClaimPrekeyBundle(&context_, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INTERNAL);
}

} // namespace
} // namespace securecloud::auth::service::test
