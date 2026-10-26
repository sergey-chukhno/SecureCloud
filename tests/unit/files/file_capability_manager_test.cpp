#include "files/service/file_capability_manager.hpp"

#include <gtest/gtest.h>

namespace securecloud::files {
namespace {

using auth::crypto::Ed25519TokenSigner;
using auth::crypto::Ed25519TokenVerifier;

class MockDeviceRevocationProvider : public IDeviceRevocationProvider {
  public:
    bool is_device_revoked(const std::string& device_id) override {
        return revoked_devices.contains(device_id);
    }
    void mark_device_revoked(const std::string& device_id) override {
        revoked_devices.insert(device_id);
    }
    void clear_revocation(const std::string& device_id) override {
        revoked_devices.erase(device_id);
    }

    std::unordered_set<std::string> revoked_devices;
};

class FileCapabilityManagerTest : public ::testing::Test {
  protected:
    void SetUp() override {
        signer_ = std::make_shared<Ed25519TokenSigner>("sc-files-test-v1");
        verifier_ = Ed25519TokenVerifier::from_signer(*signer_);
        revocation_provider_ = std::make_shared<MockDeviceRevocationProvider>();
        
        manager_ = std::make_unique<FileCapabilityManager>(
            nullptr, signer_, verifier_, revocation_provider_, nullptr);
    }

    std::shared_ptr<Ed25519TokenSigner> signer_;
    std::shared_ptr<Ed25519TokenVerifier> verifier_;
    std::shared_ptr<MockDeviceRevocationProvider> revocation_provider_;
    std::unique_ptr<FileCapabilityManager> manager_;
};

TEST_F(FileCapabilityManagerTest, IssueAndAuthorizeValidCapability) {
    const std::string uid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
    const std::string did = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002";
    const std::string fid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003";

    std::string token = manager_->issue_capability(
        uid, did, fid, FileCapabilityOperation::Read, 1, std::chrono::minutes(15));
    EXPECT_FALSE(token.empty());

    auto claims = manager_->authorize_capability(
        token, uid, did, fid, FileCapabilityOperation::Read, 1);

    EXPECT_EQ(claims.user_id, uid);
    EXPECT_EQ(claims.device_id, did);
    EXPECT_EQ(claims.file_id, fid);
    EXPECT_EQ(claims.file_version, 1);
    EXPECT_EQ(claims.operation, FileCapabilityOperation::Read);
}

TEST_F(FileCapabilityManagerTest, RejectsWrongUser) {
    const std::string uid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
    const std::string did = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002";
    const std::string fid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003";

    std::string token = manager_->issue_capability(
        uid, did, fid, FileCapabilityOperation::Read, 1);

    EXPECT_THROW(
        manager_->authorize_capability(
            token, "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099", did, fid, FileCapabilityOperation::Read, 1),
        UnauthorizedFileAccessException);
}

TEST_F(FileCapabilityManagerTest, RejectsWrongDevice) {
    const std::string uid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
    const std::string did = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002";
    const std::string fid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003";

    std::string token = manager_->issue_capability(
        uid, did, fid, FileCapabilityOperation::Read, 1);

    EXPECT_THROW(
        manager_->authorize_capability(
            token, uid, "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099", fid, FileCapabilityOperation::Read, 1),
        UnauthorizedFileAccessException);
}

TEST_F(FileCapabilityManagerTest, RejectsWrongFile) {
    const std::string uid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
    const std::string did = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002";
    const std::string fid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003";

    std::string token = manager_->issue_capability(
        uid, did, fid, FileCapabilityOperation::Read, 1);

    EXPECT_THROW(
        manager_->authorize_capability(
            token, uid, did, "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099", FileCapabilityOperation::Read, 1),
        UnauthorizedFileAccessException);
}

TEST_F(FileCapabilityManagerTest, RejectsRevokedDevice) {
    const std::string uid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
    const std::string did = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002";
    const std::string fid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003";

    std::string token = manager_->issue_capability(
        uid, did, fid, FileCapabilityOperation::Read, 1);

    // Mark device as revoked after capability issuance
    revocation_provider_->mark_device_revoked(did);

    EXPECT_THROW(
        manager_->authorize_capability(
            token, uid, did, fid, FileCapabilityOperation::Read, 1),
        UnauthorizedFileAccessException);
}

TEST_F(FileCapabilityManagerTest, RejectsMalformedToken) {
    const std::string uid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
    const std::string did = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002";
    const std::string fid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003";

    EXPECT_THROW(
        manager_->authorize_capability(
            "bad.token.signature", uid, did, fid, FileCapabilityOperation::Read, 1),
        InvalidCapabilityException);

    EXPECT_THROW(
        manager_->authorize_capability(
            "", uid, did, fid, FileCapabilityOperation::Read, 1),
        InvalidCapabilityException);
}

TEST_F(FileCapabilityManagerTest, InvalidArgumentOnBadUuid) {
    EXPECT_THROW(
        manager_->issue_capability("bad-uid", "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002",
                                   "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003", FileCapabilityOperation::Read),
        std::invalid_argument);
}

} // namespace
} // namespace securecloud::files
