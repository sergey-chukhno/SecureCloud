#include "files/domain/capability_validator.hpp"
#include "files/domain/file_capability_serializer.hpp"

#include <gtest/gtest.h>

namespace securecloud::files {
namespace {

using auth::crypto::Ed25519TokenSigner;
using auth::crypto::Ed25519TokenVerifier;

class CapabilityValidatorTest : public ::testing::Test {
  protected:
    void SetUp() override {
        signer_ = std::make_shared<Ed25519TokenSigner>("sc-files-test-v1");
        verifier_ = Ed25519TokenVerifier::from_signer(*signer_);
        validator_ = std::make_unique<CapabilityValidator>(verifier_);
    }

    FileAccessCapabilityClaims make_claims(std::string uid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001",
                                           std::string did = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002",
                                           std::string fid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003",
                                           FileCapabilityOperation op = FileCapabilityOperation::Read, int32_t ver = 0,
                                           int ttl_minutes = 15) {
        auto now = std::chrono::system_clock::now();
        return FileAccessCapabilityClaims{
            .capability_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000",
            .user_id = std::move(uid),
            .device_id = std::move(did),
            .file_id = std::move(fid),
            .file_version = ver,
            .operation = op,
            .issued_at = std::chrono::time_point_cast<std::chrono::seconds>(now - std::chrono::seconds(10)),
            .expires_at = std::chrono::time_point_cast<std::chrono::seconds>(now + std::chrono::minutes(ttl_minutes)),
            .issuer = "securecloud-files"};
    }

    std::string generate_token(const FileAccessCapabilityClaims& claims) {
        return FileCapabilitySerializer::serialize(claims, *signer_);
    }

    std::shared_ptr<Ed25519TokenSigner> signer_;
    std::shared_ptr<Ed25519TokenVerifier> verifier_;
    std::unique_ptr<CapabilityValidator> validator_;
};

TEST_F(CapabilityValidatorTest, ValidCapabilitySucceeds) {
    auto claims = make_claims();
    std::string token = generate_token(claims);

    CapabilityValidationInput input{.presented_token = token,
                                    .caller_user_id = claims.user_id,
                                    .caller_device_id = claims.device_id,
                                    .target_file_id = claims.file_id,
                                    .requested_version = 0,
                                    .requested_operation = FileCapabilityOperation::Read,
                                    .is_device_revoked = false};

    auto result = validator_->validate(input);
    EXPECT_TRUE(result.is_valid);
    EXPECT_TRUE(result.error_message.empty());
    ASSERT_TRUE(result.verified_claims.has_value());
    EXPECT_EQ(result.verified_claims->user_id, claims.user_id);
}

TEST_F(CapabilityValidatorTest, RejectsExpiredCapability) {
    auto claims = make_claims();
    // Issued in past and expired 1 hour ago
    auto now = std::chrono::system_clock::now();
    claims.issued_at = now - std::chrono::hours(2);
    claims.expires_at = now - std::chrono::hours(1);
    std::string token = generate_token(claims);

    CapabilityValidationInput input{.presented_token = token,
                                    .caller_user_id = claims.user_id,
                                    .caller_device_id = claims.device_id,
                                    .target_file_id = claims.file_id,
                                    .requested_version = 0,
                                    .requested_operation = FileCapabilityOperation::Read,
                                    .is_device_revoked = false,
                                    .current_time = now};

    auto result = validator_->validate(input);
    EXPECT_FALSE(result.is_valid);
    EXPECT_NE(result.error_message.find("expired"), std::string::npos);
}

TEST_F(CapabilityValidatorTest, RejectsWrongUser) {
    auto claims = make_claims("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    std::string token = generate_token(claims);

    CapabilityValidationInput input{.presented_token = token,
                                    .caller_user_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099", // User B
                                    .caller_device_id = claims.device_id,
                                    .target_file_id = claims.file_id,
                                    .requested_version = 0,
                                    .requested_operation = FileCapabilityOperation::Read,
                                    .is_device_revoked = false};

    auto result = validator_->validate(input);
    EXPECT_FALSE(result.is_valid);
    EXPECT_NE(result.error_message.find("user mismatch"), std::string::npos);
}

TEST_F(CapabilityValidatorTest, RejectsWrongDevice) {
    auto claims = make_claims();
    std::string token = generate_token(claims);

    CapabilityValidationInput input{.presented_token = token,
                                    .caller_user_id = claims.user_id,
                                    .caller_device_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099", // Device B
                                    .target_file_id = claims.file_id,
                                    .requested_version = 0,
                                    .requested_operation = FileCapabilityOperation::Read,
                                    .is_device_revoked = false};

    auto result = validator_->validate(input);
    EXPECT_FALSE(result.is_valid);
    EXPECT_NE(result.error_message.find("device mismatch"), std::string::npos);
}

TEST_F(CapabilityValidatorTest, RejectsWrongFile) {
    auto claims = make_claims();
    std::string token = generate_token(claims);

    CapabilityValidationInput input{.presented_token = token,
                                    .caller_user_id = claims.user_id,
                                    .caller_device_id = claims.device_id,
                                    .target_file_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099", // File B
                                    .requested_version = 0,
                                    .requested_operation = FileCapabilityOperation::Read,
                                    .is_device_revoked = false};

    auto result = validator_->validate(input);
    EXPECT_FALSE(result.is_valid);
    EXPECT_NE(result.error_message.find("file mismatch"), std::string::npos);
}

TEST_F(CapabilityValidatorTest, RejectsWrongOperation) {
    auto claims = make_claims();
    claims.operation = FileCapabilityOperation::Read;
    std::string token = generate_token(claims);

    CapabilityValidationInput input{.presented_token = token,
                                    .caller_user_id = claims.user_id,
                                    .caller_device_id = claims.device_id,
                                    .target_file_id = claims.file_id,
                                    .requested_version = 0,
                                    .requested_operation =
                                        FileCapabilityOperation::Delete, // Asking for Delete with Read cap
                                    .is_device_revoked = false};

    auto result = validator_->validate(input);
    EXPECT_FALSE(result.is_valid);
    EXPECT_NE(result.error_message.find("operation mismatch"), std::string::npos);
}

TEST_F(CapabilityValidatorTest, RejectsRevokedDevice) {
    auto claims = make_claims();
    std::string token = generate_token(claims);

    CapabilityValidationInput input{
        .presented_token = token,
        .caller_user_id = claims.user_id,
        .caller_device_id = claims.device_id,
        .target_file_id = claims.file_id,
        .requested_version = 0,
        .requested_operation = FileCapabilityOperation::Read,
        .is_device_revoked = true // Device marked revoked
    };

    auto result = validator_->validate(input);
    EXPECT_FALSE(result.is_valid);
    EXPECT_NE(result.error_message.find("revoked"), std::string::npos);
}

TEST_F(CapabilityValidatorTest, RejectsMalformedToken) {
    CapabilityValidationInput input{.presented_token = "invalid.garbage.token",
                                    .caller_user_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001",
                                    .caller_device_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002",
                                    .target_file_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003",
                                    .requested_version = 0,
                                    .requested_operation = FileCapabilityOperation::Read,
                                    .is_device_revoked = false};

    auto result = validator_->validate(input);
    EXPECT_FALSE(result.is_valid);
    EXPECT_FALSE(result.error_message.empty());
}

TEST_F(CapabilityValidatorTest, RejectsPrematureTimestampReplay) {
    auto claims = make_claims();
    auto now = std::chrono::system_clock::now();
    // Issued 1 hour in future
    claims.issued_at = now + std::chrono::hours(1);
    claims.expires_at = now + std::chrono::hours(2);
    std::string token = generate_token(claims);

    CapabilityValidationInput input{.presented_token = token,
                                    .caller_user_id = claims.user_id,
                                    .caller_device_id = claims.device_id,
                                    .target_file_id = claims.file_id,
                                    .requested_version = 0,
                                    .requested_operation = FileCapabilityOperation::Read,
                                    .is_device_revoked = false,
                                    .current_time = now};

    auto result = validator_->validate(input);
    EXPECT_FALSE(result.is_valid);
    EXPECT_NE(result.error_message.find("premature"), std::string::npos);
}

TEST_F(CapabilityValidatorTest, PinnedVersionMatching) {
    auto claims = make_claims();
    claims.file_version = 2; // Pinned to version 2
    std::string token = generate_token(claims);

    // Requesting version 2 -> success
    CapabilityValidationInput input_ok{.presented_token = token,
                                       .caller_user_id = claims.user_id,
                                       .caller_device_id = claims.device_id,
                                       .target_file_id = claims.file_id,
                                       .requested_version = 2,
                                       .requested_operation = FileCapabilityOperation::Read,
                                       .is_device_revoked = false};
    EXPECT_TRUE(validator_->validate(input_ok).is_valid);

    // Requesting version 3 -> mismatch
    CapabilityValidationInput input_bad{.presented_token = token,
                                        .caller_user_id = claims.user_id,
                                        .caller_device_id = claims.device_id,
                                        .target_file_id = claims.file_id,
                                        .requested_version = 3,
                                        .requested_operation = FileCapabilityOperation::Read,
                                        .is_device_revoked = false};
    auto bad_res = validator_->validate(input_bad);
    EXPECT_FALSE(bad_res.is_valid);
    EXPECT_NE(bad_res.error_message.find("version mismatch"), std::string::npos);
}

} // namespace
} // namespace securecloud::files
