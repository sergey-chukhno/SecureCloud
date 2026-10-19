#include "securecloud/auth/v1/auth.grpc.pb.h"
#include "securecloud/auth/v1/auth.pb.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <type_traits>
#include <vector>

namespace {

using namespace securecloud::auth::v1;

constexpr int64_t k_test_expires_at = 1727250000000LL;
constexpr int64_t k_test_validate_expires_at = 1727255000000LL;
constexpr size_t k_crypto_key_len = 32;
constexpr size_t k_crypto_sig_len = 64;
constexpr int k_prekey_count = 5;

TEST(AuthProtoSmokeTest, EnumDefaultZeroValues) {
    EXPECT_EQ(DeviceStatus::DEVICE_STATUS_UNSPECIFIED, 0);
    EXPECT_EQ(DeviceStatus::DEVICE_STATUS_ACTIVE, 1);
    EXPECT_EQ(DeviceStatus::DEVICE_STATUS_REVOKED, 2);

    EXPECT_EQ(AuthenticationLevel::AUTHENTICATION_LEVEL_UNSPECIFIED, 0);
    EXPECT_EQ(AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, 1);
    EXPECT_EQ(AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED, 2);

    EXPECT_EQ(KeyType::KEY_TYPE_UNSPECIFIED, 0);
    EXPECT_EQ(KeyType::KEY_TYPE_IDENTITY_SIGNING, 1);
    EXPECT_EQ(KeyType::KEY_TYPE_IDENTITY_AGREEMENT, 2);
    EXPECT_EQ(KeyType::KEY_TYPE_SIGNED_PREKEY, 3);
    EXPECT_EQ(KeyType::KEY_TYPE_ONE_TIME_PREKEY, 4);

    EXPECT_EQ(AccountStatus::ACCOUNT_STATUS_UNSPECIFIED, 0);
    EXPECT_EQ(AccountStatus::ACCOUNT_STATUS_ACTIVE, 1);
    EXPECT_EQ(AccountStatus::ACCOUNT_STATUS_DISABLED, 2);

    EXPECT_EQ(SessionStatus::SESSION_STATUS_UNSPECIFIED, 0);
    EXPECT_EQ(SessionStatus::SESSION_STATUS_ACTIVE, 1);
    EXPECT_EQ(SessionStatus::SESSION_STATUS_REVOKED, 2);
    EXPECT_EQ(SessionStatus::SESSION_STATUS_EXPIRED, 3);
}

TEST(AuthProtoSmokeTest, AuthenticateRoundTripSerialization) {
    AuthenticateRequest req;
    req.set_credential_identifier("user@example.com");
    req.set_password("CorrectHorseBatteryStaple");
    req.set_device_id("018f3a22-38d5-7b56-b072-000000000001");

    std::string serialized;
    EXPECT_TRUE(req.SerializeToString(&serialized));
    EXPECT_FALSE(serialized.empty());

    AuthenticateRequest restored;
    EXPECT_TRUE(restored.ParseFromString(serialized));
    EXPECT_EQ(restored.credential_identifier(), "user@example.com");
    EXPECT_EQ(restored.password(), "CorrectHorseBatteryStaple");
    EXPECT_EQ(restored.device_id(), "018f3a22-38d5-7b56-b072-000000000001");

    AuthenticateResponse resp;
    resp.set_session_id("018f3a22-38d5-7b56-b072-000000000002");
    resp.set_access_token("header.payload.signature");
    resp.set_refresh_token("opaque_refresh_token_blob");
    resp.set_authentication_level(AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    resp.set_expires_at_epoch_ms(k_test_expires_at);
    resp.set_user_id("018f3a22-38d5-7b56-b072-000000000003");
    resp.set_mfa_required(false);
    resp.set_mfa_challenge_id("");

    std::string resp_serialized;
    EXPECT_TRUE(resp.SerializeToString(&resp_serialized));

    AuthenticateResponse resp_restored;
    EXPECT_TRUE(resp_restored.ParseFromString(resp_serialized));
    EXPECT_EQ(resp_restored.session_id(), "018f3a22-38d5-7b56-b072-000000000002");
    EXPECT_EQ(resp_restored.access_token(), "header.payload.signature");
    EXPECT_EQ(resp_restored.refresh_token(), "opaque_refresh_token_blob");
    EXPECT_EQ(resp_restored.authentication_level(), AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    EXPECT_EQ(resp_restored.expires_at_epoch_ms(), k_test_expires_at);
    EXPECT_EQ(resp_restored.user_id(), "018f3a22-38d5-7b56-b072-000000000003");
    EXPECT_FALSE(resp_restored.mfa_required());
    EXPECT_TRUE(resp_restored.mfa_challenge_id().empty());
}

TEST(AuthProtoSmokeTest, ValidateAndRevokeSessionMessages) {
    ValidateSessionRequest v_req;
    v_req.set_session_id("018f3a22-38d5-7b56-b072-000000000002");
    v_req.set_access_token("token_string");

    ValidateSessionResponse v_resp;
    v_resp.set_is_valid(true);
    v_resp.set_user_id("018f3a22-38d5-7b56-b072-000000000003");
    v_resp.set_device_id("018f3a22-38d5-7b56-b072-000000000001");
    v_resp.set_authentication_level(AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    v_resp.set_expires_at_epoch_ms(k_test_validate_expires_at);

    std::string v_buf;
    EXPECT_TRUE(v_resp.SerializeToString(&v_buf));
    ValidateSessionResponse v_out;
    EXPECT_TRUE(v_out.ParseFromString(v_buf));
    EXPECT_TRUE(v_out.is_valid());
    EXPECT_EQ(v_out.user_id(), "018f3a22-38d5-7b56-b072-000000000003");

    RevokeSessionRequest r_req;
    r_req.set_session_id("018f3a22-38d5-7b56-b072-000000000002");
    r_req.set_reason("User logout");

    RevokeSessionResponse r_resp;
    r_resp.set_revoked(true);

    std::string r_buf;
    EXPECT_TRUE(r_resp.SerializeToString(&r_buf));
    RevokeSessionResponse r_out;
    EXPECT_TRUE(r_out.ParseFromString(r_buf));
    EXPECT_TRUE(r_out.revoked());
}

void verify_restored_prekeys(const RegisterDeviceRequest& restored) {
    EXPECT_EQ(restored.one_time_prekeys_size(), k_prekey_count);
    for (int i = 0; i < k_prekey_count; ++i) {
        EXPECT_EQ(restored.one_time_prekeys(i), std::string(k_crypto_key_len, static_cast<char>(i + 1)));
    }
}

TEST(AuthProtoSmokeTest, RegisterDeviceWithBinaryPrekeys) {
    RegisterDeviceRequest req;
    req.set_user_id("018f3a22-38d5-7b56-b072-000000000003");

    const std::string identity_key(k_crypto_key_len, '\x42');
    const std::string signed_prekey(k_crypto_key_len, '\x43');
    const std::string signature(k_crypto_sig_len, '\x44');

    req.set_identity_key(identity_key);
    req.set_signed_prekey(signed_prekey);
    req.set_signed_prekey_signature(signature);

    for (int i = 0; i < k_prekey_count; ++i) {
        req.add_one_time_prekeys(std::string(k_crypto_key_len, static_cast<char>(i + 1)));
    }

    std::string serialized;
    EXPECT_TRUE(req.SerializeToString(&serialized));

    RegisterDeviceRequest restored;
    EXPECT_TRUE(restored.ParseFromString(serialized));
    EXPECT_EQ(restored.user_id(), "018f3a22-38d5-7b56-b072-000000000003");
    EXPECT_EQ(restored.identity_key(), identity_key);
    EXPECT_EQ(restored.signed_prekey(), signed_prekey);
    EXPECT_EQ(restored.signed_prekey_signature(), signature);
    verify_restored_prekeys(restored);
}

TEST(AuthProtoSmokeTest, CryptoDirectoryRoundTrip) {
    GetDeviceCryptoDirectoryResponse resp;
    auto* rec = resp.add_devices();
    rec->set_device_id("018f3a22-38d5-7b56-b072-000000000001");
    rec->set_identity_key(std::string(k_crypto_key_len, '\xAA'));
    rec->set_signed_prekey(std::string(k_crypto_key_len, '\xBB'));
    rec->set_signed_prekey_signature(std::string(k_crypto_sig_len, '\xCC'));
    rec->set_one_time_prekey(std::string(k_crypto_key_len, '\xDD'));
    rec->set_one_time_prekey_id("otpk-001");

    std::string serialized;
    EXPECT_TRUE(resp.SerializeToString(&serialized));

    GetDeviceCryptoDirectoryResponse restored;
    EXPECT_TRUE(restored.ParseFromString(serialized));
    EXPECT_EQ(restored.devices_size(), 1);
    EXPECT_EQ(restored.devices(0).device_id(), "018f3a22-38d5-7b56-b072-000000000001");
    EXPECT_EQ(restored.devices(0).identity_key(), std::string(k_crypto_key_len, '\xAA'));
    EXPECT_EQ(restored.devices(0).signed_prekey(), std::string(k_crypto_key_len, '\xBB'));
    EXPECT_EQ(restored.devices(0).signed_prekey_signature(), std::string(k_crypto_sig_len, '\xCC'));
    EXPECT_EQ(restored.devices(0).one_time_prekey(), std::string(k_crypto_key_len, '\xDD'));
    EXPECT_EQ(restored.devices(0).one_time_prekey_id(), "otpk-001");
}

TEST(AuthProtoSmokeTest, ServiceStubTypeLinkage) {
    EXPECT_TRUE((std::is_same_v<AuthService::Service, AuthService::Service>));
    EXPECT_TRUE((std::is_same_v<AuthService::Stub, AuthService::Stub>));
    EXPECT_TRUE((std::is_same_v<AuthService::AsyncService, AuthService::AsyncService>));
    EXPECT_TRUE((std::is_same_v<AuthService::StubInterface, AuthService::StubInterface>));
}

} // namespace
