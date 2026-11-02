#include "client/auth_crypto_directory_client_interface.hpp"
#include "service/recipient_device_resolution_service.hpp"

#include <gtest/gtest.h>
#include <thread>

namespace securecloud::messaging::service {
namespace {

using client::CryptoDirectoryError;
using client::CryptoDirectoryErrorKind;
using client::DeviceCryptoRecord;
using client::IAuthCryptoDirectoryClient;
using client::Result;
using domain::DeviceId;
using domain::E2EAlgorithm;
using domain::E2EProtocolVersion;
using domain::PerDeviceEnvelope;
using domain::UserId;

// ============================================================================
// Mock Auth Crypto Directory Client
// ============================================================================

class MockAuthCryptoDirectoryClient : public IAuthCryptoDirectoryClient {
  public:
    void add_device(const UserId& user_id, const DeviceId& device_id,
                    securecloud::auth::v1::DeviceStatus status = securecloud::auth::v1::DEVICE_STATUS_ACTIVE) {
        DeviceCryptoRecord rec{
            .device_id = device_id,
            .user_id = user_id,
            .identity_key = std::vector<uint8_t>(32, 0x01),
            .signed_prekey = std::vector<uint8_t>(32, 0x02),
            .signed_prekey_signature = std::vector<uint8_t>(64, 0x03),
            .one_time_prekey = std::vector<uint8_t>(32, 0x04),
            .one_time_prekey_id = "otk-1",
            .status = status,
            .identity_key_fingerprint = "fp-" + device_id.str(),
            .signed_prekey_created_at_epoch_ms = 1000,
            .remaining_one_time_prekeys = 50,
        };
        user_devices_[user_id].push_back(rec);
        device_map_[device_id] = rec;
    }

    void set_simulate_failure(bool fail, CryptoDirectoryErrorKind kind = CryptoDirectoryErrorKind::ServiceUnavailable) {
        simulate_failure_ = fail;
        failure_kind_ = kind;
    }

    size_t get_call_count() const { return call_count_; }

    Result<std::vector<DeviceCryptoRecord>, CryptoDirectoryError>
    get_user_device_crypto_records(const UserId& user_id, std::chrono::milliseconds /*timeout*/) override {
        ++call_count_;
        if (simulate_failure_) {
            return CryptoDirectoryError{
                .kind = failure_kind_,
                .message = "Simulated Auth downstream network failure",
                .grpc_code = ::grpc::StatusCode::UNAVAILABLE,
            };
        }

        auto it = user_devices_.find(user_id);
        if (it != user_devices_.end()) {
            return it->second;
        }
        return std::vector<DeviceCryptoRecord>{};
    }

    Result<DeviceCryptoRecord, CryptoDirectoryError>
    get_device_crypto_identity(const DeviceId& device_id, std::chrono::milliseconds /*timeout*/) override {
        if (simulate_failure_) {
            return CryptoDirectoryError{
                .kind = failure_kind_,
                .message = "Simulated Auth downstream network failure",
                .grpc_code = ::grpc::StatusCode::UNAVAILABLE,
            };
        }

        auto it = device_map_.find(device_id);
        if (it != device_map_.end()) {
            return it->second;
        }

        return CryptoDirectoryError{
            .kind = CryptoDirectoryErrorKind::NotFound,
            .message = "Device not found",
            .grpc_code = ::grpc::StatusCode::NOT_FOUND,
        };
    }

  private:
    std::unordered_map<UserId, std::vector<DeviceCryptoRecord>> user_devices_;
    std::unordered_map<DeviceId, DeviceCryptoRecord> device_map_;
    bool simulate_failure_{false};
    CryptoDirectoryErrorKind failure_kind_{CryptoDirectoryErrorKind::ServiceUnavailable};
    size_t call_count_{0};
};

PerDeviceEnvelope make_envelope(const UserId& user_id, const DeviceId& device_id) {
    return PerDeviceEnvelope{
        .recipient_user_id = user_id,
        .recipient_device_id = device_id,
        .protocol_version = E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet,
        .algorithm = E2EAlgorithm::XChaCha20_Poly1305,
        .ciphertext_blob = "valid-ciphertext",
        .ephemeral_public_key = std::vector<uint8_t>(32, 0x11),
        .iv = std::vector<uint8_t>(24, 0x22),
        .auth_tag = std::vector<uint8_t>(16, 0x33),
        .one_time_prekey_id = std::nullopt,
    };
}

// ============================================================================
// DeviceDirectoryCache Unit Tests
// ============================================================================

TEST(DeviceDirectoryCacheTest, PutAndGet) {
    DeviceDirectoryCache cache(10, std::chrono::milliseconds(5000));
    UserId user{"018f2d52-0000-7000-8000-000000000001"};

    EXPECT_FALSE(cache.get(user).has_value());
    EXPECT_EQ(cache.size(), 0u);

    DeviceCryptoRecord rec{
        .device_id = DeviceId{"dev-1"},
        .user_id = user,
    };
    cache.put(user, {rec});

    EXPECT_EQ(cache.size(), 1u);
    auto cached = cache.get(user);
    ASSERT_TRUE(cached.has_value());
    ASSERT_EQ(cached->size(), 1u);
    EXPECT_EQ((*cached)[0].device_id, DeviceId{"dev-1"});
}

TEST(DeviceDirectoryCacheTest, TtlExpiration) {
    // 50ms TTL
    DeviceDirectoryCache cache(10, std::chrono::milliseconds(50));
    UserId user{"018f2d52-0000-7000-8000-000000000001"};

    cache.put(user, {});
    EXPECT_TRUE(cache.get(user).has_value());

    std::this_thread::sleep_for(std::chrono::milliseconds(70));
    EXPECT_FALSE(cache.get(user).has_value());
}

TEST(DeviceDirectoryCacheTest, LruEvictionAtCapacity) {
    DeviceDirectoryCache cache(2, std::chrono::milliseconds(60000));
    UserId u1{"018f2d52-0000-7000-8000-000000000001"};
    UserId u2{"018f2d52-0000-7000-8000-000000000002"};
    UserId u3{"018f2d52-0000-7000-8000-000000000003"};

    cache.put(u1, {});
    cache.put(u2, {});
    EXPECT_EQ(cache.size(), 2u);

    // Access u1 so u2 becomes least recently used
    EXPECT_TRUE(cache.get(u1).has_value());

    // Insert u3 -> should evict u2
    cache.put(u3, {});
    EXPECT_EQ(cache.size(), 2u);

    EXPECT_TRUE(cache.get(u1).has_value());
    EXPECT_FALSE(cache.get(u2).has_value());
    EXPECT_TRUE(cache.get(u3).has_value());
}

TEST(DeviceDirectoryCacheTest, ExplicitInvalidationAndClear) {
    DeviceDirectoryCache cache(10, std::chrono::milliseconds(60000));
    UserId u1{"018f2d52-0000-7000-8000-000000000001"};
    UserId u2{"018f2d52-0000-7000-8000-000000000002"};

    cache.put(u1, {});
    cache.put(u2, {});
    EXPECT_EQ(cache.size(), 2u);

    cache.invalidate(u1);
    EXPECT_FALSE(cache.get(u1).has_value());
    EXPECT_TRUE(cache.get(u2).has_value());
    EXPECT_EQ(cache.size(), 1u);

    cache.clear();
    EXPECT_EQ(cache.size(), 0u);
    EXPECT_FALSE(cache.get(u2).has_value());
}

// ============================================================================
// RecipientDeviceResolutionService Unit Tests
// ============================================================================

TEST(RecipientDeviceResolutionServiceTest, HappyPathAllActiveDevicesTargeted) {
    auto mock_client = std::make_shared<MockAuthCryptoDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    UserId bob{"018f2d52-0000-7000-8000-000000000002"};
    DeviceId dev_alice1{"dev-alice-1"};
    DeviceId dev_alice2{"dev-alice-2"};
    DeviceId dev_bob1{"dev-bob-1"};

    mock_client->add_device(alice, dev_alice1, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    mock_client->add_device(alice, dev_alice2, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    mock_client->add_device(bob, dev_bob1, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);

    RecipientDeviceResolutionService service(mock_client);

    std::vector<UserId> participants = {alice, bob};
    std::vector<PerDeviceEnvelope> envelopes = {
        make_envelope(alice, dev_alice1),
        make_envelope(alice, dev_alice2),
    };

    auto result =
        service.validate_submission_targets(participants, envelopes, dev_bob1, bob, /*enforce_completeness=*/true);

    EXPECT_TRUE(result.is_valid);
    EXPECT_TRUE(result.omitted_device_ids.empty());
    EXPECT_EQ(result.error_message, "");
}

TEST(RecipientDeviceResolutionServiceTest, CacheEliminatesRedundantDownstreamRpc) {
    auto mock_client = std::make_shared<MockAuthCryptoDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    DeviceId dev_alice{"dev-alice-1"};
    mock_client->add_device(alice, dev_alice);

    RecipientDeviceResolutionService service(mock_client);

    EXPECT_EQ(mock_client->get_call_count(), 0u);

    // Call 1 -> cache miss -> RPC
    auto r1 = service.resolve_devices_for_user(alice);
    EXPECT_TRUE(r1.has_value());
    EXPECT_EQ(mock_client->get_call_count(), 1u);

    // Call 2 -> cache hit -> no RPC
    auto r2 = service.resolve_devices_for_user(alice);
    EXPECT_TRUE(r2.has_value());
    EXPECT_EQ(mock_client->get_call_count(), 1u);

    // Invalidate -> Call 3 -> cache miss -> RPC
    service.invalidate_user_cache(alice);
    auto r3 = service.resolve_devices_for_user(alice);
    EXPECT_TRUE(r3.has_value());
    EXPECT_EQ(mock_client->get_call_count(), 2u);
}

TEST(RecipientDeviceResolutionServiceTest, RejectsNonParticipantTarget) {
    auto mock_client = std::make_shared<MockAuthCryptoDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    UserId charlie{"018f2d52-0000-7000-8000-000000000003"};
    DeviceId dev_charlie{"dev-charlie-1"};
    mock_client->add_device(charlie, dev_charlie);

    RecipientDeviceResolutionService service(mock_client);

    std::vector<UserId> participants = {alice};
    std::vector<PerDeviceEnvelope> envelopes = {
        make_envelope(charlie, dev_charlie),
    };

    auto result = service.validate_submission_targets(participants, envelopes);
    EXPECT_FALSE(result.is_valid);
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT);
    EXPECT_NE(result.error_message.find("not a participant"), std::string::npos);
}

TEST(RecipientDeviceResolutionServiceTest, RejectsMismatchedDeviceOwnership) {
    auto mock_client = std::make_shared<MockAuthCryptoDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    UserId bob{"018f2d52-0000-7000-8000-000000000002"};
    DeviceId dev_bob{"dev-bob-1"};

    mock_client->add_device(bob, dev_bob);

    RecipientDeviceResolutionService service(mock_client);

    std::vector<UserId> participants = {alice, bob};
    // Attack scenario: claim dev_bob belongs to alice
    std::vector<PerDeviceEnvelope> envelopes = {
        make_envelope(alice, dev_bob),
    };

    auto result = service.validate_submission_targets(participants, envelopes);
    EXPECT_FALSE(result.is_valid);
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);
    EXPECT_NE(result.error_message.find("does not belong to recipient"), std::string::npos);
}

TEST(RecipientDeviceResolutionServiceTest, RejectsRevokedTargetDevice) {
    auto mock_client = std::make_shared<MockAuthCryptoDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    DeviceId dev_alice_lost{"dev-alice-lost"};

    mock_client->add_device(alice, dev_alice_lost, securecloud::auth::v1::DEVICE_STATUS_REVOKED);

    RecipientDeviceResolutionService service(mock_client);

    std::vector<UserId> participants = {alice};
    std::vector<PerDeviceEnvelope> envelopes = {
        make_envelope(alice, dev_alice_lost),
    };

    auto result = service.validate_submission_targets(participants, envelopes);
    EXPECT_FALSE(result.is_valid);
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED);
    EXPECT_NE(result.error_message.find("has been revoked"), std::string::npos);
}

TEST(RecipientDeviceResolutionServiceTest, RejectsPendingTargetDevice) {
    auto mock_client = std::make_shared<MockAuthCryptoDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    DeviceId dev_alice_pending{"dev-alice-pending"};

    mock_client->add_device(alice, dev_alice_pending, securecloud::auth::v1::DEVICE_STATUS_PENDING_AUTHORIZATION);

    RecipientDeviceResolutionService service(mock_client);

    std::vector<UserId> participants = {alice};
    std::vector<PerDeviceEnvelope> envelopes = {
        make_envelope(alice, dev_alice_pending),
    };

    auto result = service.validate_submission_targets(participants, envelopes);
    EXPECT_FALSE(result.is_valid);
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED);
    EXPECT_NE(result.error_message.find("is not active"), std::string::npos);
}

TEST(RecipientDeviceResolutionServiceTest, RejectsRevokedSenderDevice) {
    auto mock_client = std::make_shared<MockAuthCryptoDirectoryClient>();
    UserId sender{"018f2d52-0000-7000-8000-000000000001"};
    UserId recipient{"018f2d52-0000-7000-8000-000000000002"};
    DeviceId sender_dev{"dev-sender-revoked"};
    DeviceId recp_dev{"dev-recp-1"};

    mock_client->add_device(sender, sender_dev, securecloud::auth::v1::DEVICE_STATUS_REVOKED);
    mock_client->add_device(recipient, recp_dev, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);

    RecipientDeviceResolutionService service(mock_client);

    std::vector<UserId> participants = {sender, recipient};
    std::vector<PerDeviceEnvelope> envelopes = {
        make_envelope(recipient, recp_dev),
    };

    auto result = service.validate_submission_targets(participants, envelopes, sender_dev, sender);
    EXPECT_FALSE(result.is_valid);
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED);
    EXPECT_NE(result.error_message.find("Sender device"), std::string::npos);
}

TEST(RecipientDeviceResolutionServiceTest, DetectsSelectiveDeviceOmission) {
    auto mock_client = std::make_shared<MockAuthCryptoDirectoryClient>();
    UserId sender{"018f2d52-0000-7000-8000-000000000001"};
    UserId alice{"018f2d52-0000-7000-8000-000000000002"};
    DeviceId sender_dev{"dev-sender"};
    DeviceId dev_phone{"alice-phone"};
    DeviceId dev_laptop{"alice-laptop"};

    mock_client->add_device(sender, sender_dev, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    mock_client->add_device(alice, dev_phone, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    mock_client->add_device(alice, dev_laptop, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);

    RecipientDeviceResolutionService service(mock_client);

    std::vector<UserId> participants = {sender, alice};
    // Malicious or incomplete submission: only targets alice-phone, omitting alice-laptop
    std::vector<PerDeviceEnvelope> envelopes = {
        make_envelope(alice, dev_phone),
    };

    // Case 1: enforce_completeness = false -> valid, but omitted_device_ids is populated
    auto r1 = service.validate_submission_targets(participants, envelopes, sender_dev, sender,
                                                  /*enforce_completeness=*/false);
    EXPECT_TRUE(r1.is_valid);
    ASSERT_EQ(r1.omitted_device_ids.size(), 1u);
    EXPECT_EQ(r1.omitted_device_ids[0], dev_laptop);

    // Case 2: enforce_completeness = true -> invalid
    auto r2 =
        service.validate_submission_targets(participants, envelopes, sender_dev, sender, /*enforce_completeness=*/true);
    EXPECT_FALSE(r2.is_valid);
    EXPECT_EQ(r2.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);
    ASSERT_EQ(r2.omitted_device_ids.size(), 1u);
    EXPECT_EQ(r2.omitted_device_ids[0], dev_laptop);
}

TEST(RecipientDeviceResolutionServiceTest, PropagatesDownstreamAuthFailure) {
    auto mock_client = std::make_shared<MockAuthCryptoDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    DeviceId dev_alice{"dev-alice-1"};

    mock_client->set_simulate_failure(true);

    RecipientDeviceResolutionService service(mock_client);

    std::vector<UserId> participants = {alice};
    std::vector<PerDeviceEnvelope> envelopes = {
        make_envelope(alice, dev_alice),
    };

    auto result = service.validate_submission_targets(participants, envelopes);
    EXPECT_FALSE(result.is_valid);
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_UNSPECIFIED);
    EXPECT_NE(result.error_message.find("Failed to query Auth device directory"), std::string::npos);
}

TEST(RecipientDeviceResolutionServiceTest, RejectsEmptyTargetEnvelopes) {
    auto mock_client = std::make_shared<MockAuthCryptoDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};

    RecipientDeviceResolutionService service(mock_client);

    std::vector<UserId> participants = {alice};
    std::vector<PerDeviceEnvelope> empty_envelopes{};

    auto result = service.validate_submission_targets(participants, empty_envelopes);
    EXPECT_FALSE(result.is_valid);
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);
    EXPECT_NE(result.error_message.find("no delivery targets"), std::string::npos);
}

TEST(RecipientDeviceResolutionServiceTest, RejectsSenderTargetingItself) {
    auto mock_client = std::make_shared<MockAuthCryptoDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    UserId bob{"018f2d52-0000-7000-8000-000000000002"};
    DeviceId dev_alice_phone{"dev-alice-phone"};
    DeviceId dev_bob_phone{"dev-bob-phone"};

    mock_client->add_device(alice, dev_alice_phone, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    mock_client->add_device(bob, dev_bob_phone, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);

    RecipientDeviceResolutionService service(mock_client);

    std::vector<UserId> participants = {alice, bob};
    // Alice Phone (sender) targets itself alongside Bob
    std::vector<PerDeviceEnvelope> envelopes = {
        make_envelope(alice, dev_alice_phone),
        make_envelope(bob, dev_bob_phone),
    };

    auto result = service.validate_submission_targets(participants, envelopes, dev_alice_phone, alice);
    EXPECT_FALSE(result.is_valid);
    EXPECT_EQ(result.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);
    EXPECT_NE(result.error_message.find("cannot target itself"), std::string::npos);
}

TEST(RecipientDeviceResolutionServiceTest, SenderCompanionDeviceFanoutCompleteness) {
    auto mock_client = std::make_shared<MockAuthCryptoDirectoryClient>();
    UserId alice{"018f2d52-0000-7000-8000-000000000001"};
    UserId bob{"018f2d52-0000-7000-8000-000000000002"};
    DeviceId dev_alice_phone{"dev-alice-phone"};
    DeviceId dev_alice_laptop{"dev-alice-laptop"};
    DeviceId dev_bob_phone{"dev-bob-phone"};

    mock_client->add_device(alice, dev_alice_phone, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    mock_client->add_device(alice, dev_alice_laptop, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);
    mock_client->add_device(bob, dev_bob_phone, securecloud::auth::v1::DEVICE_STATUS_ACTIVE);

    RecipientDeviceResolutionService service(mock_client);

    std::vector<UserId> participants = {alice, bob};

    // Case 1: Alice Phone submits targeting Bob Phone and Alice Laptop (companion) -> Complete
    std::vector<PerDeviceEnvelope> complete_envelopes = {
        make_envelope(alice, dev_alice_laptop),
        make_envelope(bob, dev_bob_phone),
    };
    auto r1 = service.validate_submission_targets(participants, complete_envelopes, dev_alice_phone, alice,
                                                  /*enforce_completeness=*/true);
    EXPECT_TRUE(r1.is_valid);
    EXPECT_TRUE(r1.omitted_device_ids.empty());

    // Case 2: Alice Phone submits targeting only Bob Phone, omitting companion Alice Laptop
    std::vector<PerDeviceEnvelope> incomplete_envelopes = {
        make_envelope(bob, dev_bob_phone),
    };

    // Under enforce_completeness = false -> valid, but omitted_device_ids contains Alice Laptop
    auto r2 = service.validate_submission_targets(participants, incomplete_envelopes, dev_alice_phone, alice,
                                                  /*enforce_completeness=*/false);
    EXPECT_TRUE(r2.is_valid);
    ASSERT_EQ(r2.omitted_device_ids.size(), 1u);
    EXPECT_EQ(r2.omitted_device_ids[0], dev_alice_laptop);

    // Under enforce_completeness = true -> rejected with INVALID_TARGET_DEVICE
    auto r3 = service.validate_submission_targets(participants, incomplete_envelopes, dev_alice_phone, alice,
                                                  /*enforce_completeness=*/true);
    EXPECT_FALSE(r3.is_valid);
    EXPECT_EQ(r3.error_code, v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE);
    ASSERT_EQ(r3.omitted_device_ids.size(), 1u);
    EXPECT_EQ(r3.omitted_device_ids[0], dev_alice_laptop);
    EXPECT_NE(r3.error_message.find("sender companion devices were omitted"), std::string::npos);
}

} // namespace
} // namespace securecloud::messaging::service
