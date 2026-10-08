#include "auth/crypto/device_key_validator.hpp"
#include "auth/domain/audit_event.hpp"
#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/session_result.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/repository/device_public_key_repository.hpp"
#include "auth/repository/device_repository.hpp"
#include "auth/service/audit_event_publisher.hpp"
#include "auth/service/device_manager.hpp"
#include "auth/service/session_manager.hpp"

#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::auth::service::test {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::StrictMock;

using domain::AuthenticationLevel;
using domain::DeviceEntity;
using domain::DevicePublicKeyEntity;
using domain::DeviceStatus;
using domain::SessionEntity;
using domain::SessionRevocationResult;
using domain::Uuid;

// ============================================================================
// Mocks
// ============================================================================

class MockDeviceRepository : public repository::IDeviceRepository {
  public:
    MOCK_METHOD(void, register_device, (const DeviceEntity& device), (override));
    MOCK_METHOD(void, register_device, (const DeviceEntity& device, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(std::optional<DeviceEntity>, find_by_id, (const Uuid& device_id), (override));
    MOCK_METHOD(std::optional<DeviceEntity>, find_by_id, (const Uuid& device_id, pqxx::transaction_base& tx),
                (override));

    MOCK_METHOD(std::vector<DeviceEntity>, list_active_by_user_id, (const Uuid& user_id), (override));
    MOCK_METHOD(std::vector<DeviceEntity>, list_active_by_user_id, (const Uuid& user_id, pqxx::transaction_base& tx),
                (override));

    MOCK_METHOD(std::vector<DeviceEntity>, list_all_by_user_id, (const Uuid& user_id, bool include_revoked),
                (override));
    MOCK_METHOD(std::vector<DeviceEntity>, list_all_by_user_id,
                (const Uuid& user_id, bool include_revoked, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(void, authorize_device, (const Uuid& device_id, domain::time_point authorized_at), (override));
    MOCK_METHOD(void, authorize_device,
                (const Uuid& device_id, domain::time_point authorized_at, pqxx::transaction_base& tx), (override));

    void revoke_device(const Uuid& device_id, std::string_view reason, domain::time_point revoked_at) override {
        revoke_device_str(device_id, std::string(reason), revoked_at);
    }
    MOCK_METHOD(void, revoke_device_str,
                (const Uuid& device_id, const std::string& reason, domain::time_point revoked_at));

    void revoke_device(const Uuid& device_id, std::string_view reason, domain::time_point revoked_at,
                       pqxx::transaction_base& tx) override {
        revoke_device_tx_str(device_id, std::string(reason), revoked_at, tx);
    }
    MOCK_METHOD(void, revoke_device_tx_str,
                (const Uuid& device_id, const std::string& reason, domain::time_point revoked_at,
                 pqxx::transaction_base& tx));

    MOCK_METHOD(void, update_last_authenticated, (const Uuid& device_id, domain::time_point auth_time), (override));
    MOCK_METHOD(void, update_last_authenticated,
                (const Uuid& device_id, domain::time_point auth_time, pqxx::transaction_base& tx), (override));
};

class MockDevicePublicKeyRepository : public repository::IDevicePublicKeyRepository {
  public:
    MOCK_METHOD(void, store_public_key, (const DevicePublicKeyEntity& key), (override));
    MOCK_METHOD(void, store_public_key, (const DevicePublicKeyEntity& key, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(std::optional<DevicePublicKeyEntity>, find_by_id, (const Uuid& key_id), (override));
    MOCK_METHOD(std::optional<DevicePublicKeyEntity>, find_by_id, (const Uuid& key_id, pqxx::transaction_base& tx),
                (override));

    MOCK_METHOD(std::vector<DevicePublicKeyEntity>, list_active_keys_by_device_id, (const Uuid& device_id), (override));
    MOCK_METHOD(std::vector<DevicePublicKeyEntity>, list_active_keys_by_device_id,
                (const Uuid& device_id, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(void, replace_key, (const Uuid& old_key_id, const DevicePublicKeyEntity& new_key), (override));
    MOCK_METHOD(void, replace_key,
                (const Uuid& old_key_id, const DevicePublicKeyEntity& new_key, pqxx::transaction_base& tx), (override));

    MOCK_METHOD(void, revoke_all_device_keys, (const Uuid& device_id, domain::time_point revoked_at), (override));
    MOCK_METHOD(void, revoke_all_device_keys,
                (const Uuid& device_id, domain::time_point revoked_at, pqxx::transaction_base& tx), (override));
};

class MockSessionManager : public ISessionManager {
  public:
    MOCK_METHOD(SessionEstablishmentResult, establish_session, (const domain::UserEntity&, const domain::Uuid&),
                (override));
    MOCK_METHOD(domain::SessionValidationResult, validate_session, (const domain::Uuid&, std::optional<domain::Uuid>),
                (override));
    MOCK_METHOD(std::vector<domain::SessionEntity>, list_active_sessions_for_user, (const domain::Uuid&), (override));
    MOCK_METHOD(std::vector<domain::SessionEntity>, list_active_sessions_for_device, (const domain::Uuid&), (override));
    domain::SessionRevocationResult revoke_session(const domain::Uuid& session_id, std::string_view reason) override {
        return revoke_session_str(session_id, std::string(reason));
    }
    MOCK_METHOD(domain::SessionRevocationResult, revoke_session_str, (const domain::Uuid&, const std::string&));

    domain::SessionRevocationResult revoke_all_device_sessions(const domain::Uuid& device_id,
                                                               std::string_view reason) override {
        return revoke_all_device_sessions_str(device_id, std::string(reason));
    }
    MOCK_METHOD(domain::SessionRevocationResult, revoke_all_device_sessions_str,
                (const domain::Uuid&, const std::string&));

    domain::SessionRevocationResult revoke_all_user_sessions(const domain::Uuid& user_id,
                                                             std::string_view reason) override {
        return revoke_all_user_sessions_str(user_id, std::string(reason));
    }
    MOCK_METHOD(domain::SessionRevocationResult, revoke_all_user_sessions_str,
                (const domain::Uuid&, const std::string&));
};

class MockAuditEventPublisher : public IAuditEventPublisher {
  public:
    MOCK_METHOD(void, publish, (const domain::AuditEvent& event), (noexcept, override));
};

// ============================================================================
// Test Fixture
// ============================================================================

class DeviceRevocationTest : public ::testing::Test {
  protected:
    std::shared_ptr<NiceMock<MockDeviceRepository>> device_repo_{std::make_shared<NiceMock<MockDeviceRepository>>()};
    std::shared_ptr<NiceMock<MockDevicePublicKeyRepository>> public_key_repo_{
        std::make_shared<NiceMock<MockDevicePublicKeyRepository>>()};
    std::shared_ptr<NiceMock<MockSessionManager>> session_manager_{std::make_shared<NiceMock<MockSessionManager>>()};
    std::shared_ptr<NiceMock<MockAuditEventPublisher>> audit_publisher_{
        std::make_shared<NiceMock<MockAuditEventPublisher>>()};

    DeviceManager manager_{device_repo_, public_key_repo_, session_manager_, audit_publisher_};

    Uuid user_id_{Uuid::generate_v7()};
    Uuid device_id_{Uuid::generate_v7()};

    DeviceEntity make_active_device() {
        const auto now = std::chrono::system_clock::now();
        return DeviceEntity{
            .device_id = device_id_,
            .user_id = user_id_,
            .device_status = DeviceStatus::Active,
            .registered_at = now - std::chrono::hours(1),
            .revoked_at = std::nullopt,
            .revocation_reason = std::nullopt,
            .last_authenticated_at = now - std::chrono::minutes(10),
            .created_at = now - std::chrono::hours(1),
            .updated_at = now,
        };
    }
};

// ============================================================================
// Revocation Tests
// ============================================================================

TEST_F(DeviceRevocationTest, RevokeDevice_RequiresMfaVerified_RejectsPrimaryOnly) {
    auto active_dev = make_active_device();
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).Times(0);
    EXPECT_CALL(*device_repo_, revoke_device_str(_, _, _)).Times(0);
    EXPECT_CALL(*session_manager_, revoke_all_device_sessions_str(_, _)).Times(0);
    EXPECT_CALL(*public_key_repo_, revoke_all_device_keys(_, _)).Times(0);

    auto result = manager_.revoke_device(user_id_, device_id_, "Lost device", AuthenticationLevel::PrimaryOnly);

    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.is_permission_denied);
    EXPECT_FALSE(result.is_not_found);
    EXPECT_THAT(result.error_message, ::testing::HasSubstr("MFA_VERIFIED"));
}

TEST_F(DeviceRevocationTest, RevokeDevice_CascadesToSessionManagerAndPublicKeyRepository) {
    auto active_dev = make_active_device();
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(active_dev));
    EXPECT_CALL(*device_repo_, revoke_device_str(device_id_, "Lost phone", _)).Times(1);
    EXPECT_CALL(*session_manager_, revoke_all_device_sessions_str(device_id_, "Lost phone"))
        .WillOnce(Return(SessionRevocationResult::success(2)));
    EXPECT_CALL(*public_key_repo_, revoke_all_device_keys(device_id_, _)).Times(1);

    auto result =
        manager_.revoke_device(user_id_, device_id_, "Lost phone", AuthenticationLevel::MfaVerified, "192.168.1.50");

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.device_id, device_id_);
    EXPECT_FALSE(result.is_permission_denied);
    EXPECT_FALSE(result.is_not_found);
}

TEST_F(DeviceRevocationTest, RevokeDevice_EvictsPendingPairingChallenge) {
    // 1. Put device into pending state
    DeviceEntity pending_dev = make_active_device();
    pending_dev.device_status = DeviceStatus::PendingAuthorization;

    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillRepeatedly(Return(pending_dev));

    // Initiate pairing challenge
    auto challenge_opt = manager_.initiate_device_pairing(user_id_, device_id_);
    ASSERT_TRUE(challenge_opt.has_value());
    const std::string pairing_code = challenge_opt->pairing_code;

    // 2. Revoke device
    EXPECT_CALL(*device_repo_, revoke_device_str(device_id_, _, _)).Times(1);
    EXPECT_CALL(*session_manager_, revoke_all_device_sessions_str(device_id_, _))
        .WillOnce(Return(SessionRevocationResult::success(0)));
    EXPECT_CALL(*public_key_repo_, revoke_all_device_keys(device_id_, _)).Times(1);

    auto revoke_res = manager_.revoke_device(user_id_, device_id_, "Revoked before pairing completed",
                                             AuthenticationLevel::MfaVerified);
    EXPECT_TRUE(revoke_res.success);

    // 3. Attempting to authorize using the pairing code must fail because challenge was evicted
    auto auth_res = manager_.authorize_device(user_id_, device_id_, pairing_code, AuthenticationLevel::PrimaryOnly);
    EXPECT_FALSE(auth_res.success);
    EXPECT_THAT(auth_res.error_message, ::testing::HasSubstr("Pairing challenge not found"));
}

TEST_F(DeviceRevocationTest, RevokeDevice_EmitsDeviceRevokedAuditEvent) {
    auto active_dev = make_active_device();
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(active_dev));

    domain::AuditEvent emitted_event;
    EXPECT_CALL(*audit_publisher_, publish(_)).WillOnce(SaveArg<0>(&emitted_event));

    auto result =
        manager_.revoke_device(user_id_, device_id_, "Stolen hardware", AuthenticationLevel::MfaVerified, "10.0.0.42");

    EXPECT_TRUE(result.success);
    EXPECT_EQ(emitted_event.event_type, domain::AuditEventType::DeviceRevoked);
    EXPECT_EQ(emitted_event.user_id, user_id_);
    EXPECT_EQ(emitted_event.device_id, device_id_);
    EXPECT_EQ(emitted_event.failure_reason, "Stolen hardware");
    EXPECT_EQ(emitted_event.client_ip, "10.0.0.42");
}

TEST_F(DeviceRevocationTest, RevokeDevice_WrongUser_RejectsPermissionDenied) {
    auto active_dev = make_active_device();
    // Device belongs to user_id_, but caller is other_user
    Uuid other_user = Uuid::generate_v7();
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(active_dev));
    EXPECT_CALL(*device_repo_, revoke_device_str(_, _, _)).Times(0);
    EXPECT_CALL(*session_manager_, revoke_all_device_sessions_str(_, _)).Times(0);

    auto result = manager_.revoke_device(other_user, device_id_, "Hacker attempt", AuthenticationLevel::MfaVerified);

    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.is_permission_denied);
    EXPECT_THAT(result.error_message, ::testing::HasSubstr("belongs to another user"));
}

TEST_F(DeviceRevocationTest, RevokeDevice_NotFound_RejectsNotFound) {
    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(*device_repo_, revoke_device_str(_, _, _)).Times(0);
    EXPECT_CALL(*session_manager_, revoke_all_device_sessions_str(_, _)).Times(0);

    auto result = manager_.revoke_device(user_id_, device_id_, "Non-existent", AuthenticationLevel::MfaVerified);

    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.is_not_found);
    EXPECT_THAT(result.error_message, ::testing::HasSubstr("Device not found"));
}

TEST_F(DeviceRevocationTest, RevokeDevice_AlreadyRevoked_IsIdempotent) {
    auto revoked_dev = make_active_device();
    revoked_dev.device_status = DeviceStatus::Revoked;
    revoked_dev.revoked_at = std::chrono::system_clock::now() - std::chrono::hours(2);
    revoked_dev.revocation_reason = "Previously revoked";

    EXPECT_CALL(*device_repo_, find_by_id(device_id_)).WillOnce(Return(revoked_dev));
    // Must NOT call repository or cascade again
    EXPECT_CALL(*device_repo_, revoke_device_str(_, _, _)).Times(0);
    EXPECT_CALL(*session_manager_, revoke_all_device_sessions_str(_, _)).Times(0);
    EXPECT_CALL(*public_key_repo_, revoke_all_device_keys(_, _)).Times(0);
    EXPECT_CALL(*audit_publisher_, publish(_)).Times(0);

    auto result = manager_.revoke_device(user_id_, device_id_, "Repeated call", AuthenticationLevel::MfaVerified);

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.device_id, device_id_);
    EXPECT_FALSE(result.is_permission_denied);
    EXPECT_FALSE(result.is_not_found);
}

} // namespace
} // namespace securecloud::auth::service::test
