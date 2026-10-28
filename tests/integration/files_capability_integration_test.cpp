#include "files/domain/file_capability_serializer.hpp"
#include "files/service/download_manager.hpp"
#include "files/service/file_capability_manager.hpp"
#include "files/service/files_service_impl.hpp"

#include <gtest/gtest.h>
#include <iomanip>
#include <openssl/sha.h>
#include <sstream>

namespace securecloud::files {
namespace {

using namespace securecloud::files::service;
using auth::crypto::Ed25519TokenSigner;
using auth::crypto::Ed25519TokenVerifier;

std::string compute_sha256(std::string_view data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
    std::ostringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

class TestAuthPropertyIterator : public grpc::AuthPropertyIterator {
  public:
    TestAuthPropertyIterator() = default;
};

class TestIntegrationAuthContext : public grpc::AuthContext {
  public:
    explicit TestIntegrationAuthContext(std::string san) : san_(std::move(san)) {}

    [[nodiscard]] bool IsPeerAuthenticated() const override { return true; }
    [[nodiscard]] std::string GetPeerIdentityPropertyName() const override { return "x509_subject_alternative_name"; }
    [[nodiscard]] std::vector<grpc::string_ref> GetPeerIdentity() const override {
        return {grpc::string_ref(san_.data(), san_.size())};
    }
    [[nodiscard]] std::vector<grpc::string_ref> FindPropertyValues(const std::string& name) const override {
        if (name == "x509_subject_alternative_name") {
            return {grpc::string_ref(san_.data(), san_.size())};
        }
        return {};
    }
    [[nodiscard]] grpc::AuthPropertyIterator begin() const override { return TestAuthPropertyIterator{}; }
    [[nodiscard]] grpc::AuthPropertyIterator end() const override { return TestAuthPropertyIterator{}; }
    void AddProperty(const std::string&, const grpc::string_ref&) override {}
    bool SetPeerIdentityPropertyName(const std::string&) override { return false; }

  private:
    std::string san_;
};

class FakeDownloadManager : public IDownloadManager {
  public:
    bool authorize_download(const std::string&, const std::string&) override { return true; }

    std::optional<DownloadChunkResult> get_chunk(const std::string&, uint32_t) override { return std::nullopt; }

    DownloadChunkResult get_chunk_versioned(const std::string& file_id, int32_t version_number, uint32_t chunk_index,
                                            const std::string&) override {
        // Deterministic ciphertext payload simulation
        std::string ciphertext = "ENCRYPTED_CIPHERTEXT_CHUNK_" + std::to_string(chunk_index);
        return DownloadChunkResult{.file_id = file_id,
                                   .version_number = version_number == 0 ? 1 : version_number,
                                   .chunk_index = chunk_index,
                                   .encrypted_data = ciphertext,
                                   .chunk_size_bytes = static_cast<uint32_t>(ciphertext.size()),
                                   .ciphertext_sha256 = compute_sha256(ciphertext)};
    }

    DownloadResumeModel prepare_resume_session(const std::string& file_id, int32_t version_number,
                                               uint32_t starting_chunk, const std::string&) override {
        return DownloadResumeModel{.file_id = file_id,
                                   .version_number = version_number,
                                   .starting_chunk = starting_chunk,
                                   .total_chunks = 3,
                                   .total_bytes = 1024,
                                   .ciphertext_sha256 = "dummy"};
    }
};

class FilesCapabilityIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        signer_ = std::make_shared<Ed25519TokenSigner>("sc-files-integ-v1");
        verifier_ = Ed25519TokenVerifier::from_signer(*signer_);
        revocation_provider_ = std::make_shared<DeviceRevocationProvider>(nullptr);

        capability_manager_ =
            std::make_shared<FileCapabilityManager>(nullptr, signer_, verifier_, revocation_provider_, nullptr);

        download_manager_ = std::make_shared<FakeDownloadManager>();

        service::FilesServiceDependencies deps{.download_manager = download_manager_,
                                               .capability_manager = capability_manager_};

        service_ = std::make_unique<service::FilesServiceImpl>(deps, "gateway");
    }

    std::string issue_token(const std::string& uid, const std::string& did, const std::string& fid,
                            FileCapabilityOperation op = FileCapabilityOperation::Read, int32_t ver = 0,
                            std::chrono::seconds ttl = std::chrono::minutes(15)) {
        return capability_manager_->issue_capability(uid, did, fid, op, ver, ttl);
    }

    grpc::Status execute_download(const std::string& fid, uint32_t chunk_idx, const std::string& uid,
                                  const std::string& did, const std::string& capability_token,
                                  v1::DownloadChunkResponse& resp) {
        v1::DownloadChunkRequest req;
        req.set_file_id(fid);
        req.set_chunk_index(chunk_idx);

        std::multimap<grpc::string_ref, grpc::string_ref> metadata = {
            {"x-user-id", uid}, {"x-device-id", did}, {"x-file-access-capability", capability_token}};

        TestIntegrationAuthContext auth_ctx("DNS:gateway");
        return service_->DownloadChunk(&auth_ctx, &req, &resp, metadata);
    }

    std::shared_ptr<Ed25519TokenSigner> signer_;
    std::shared_ptr<Ed25519TokenVerifier> verifier_;
    std::shared_ptr<DeviceRevocationProvider> revocation_provider_;
    std::shared_ptr<FileCapabilityManager> capability_manager_;
    std::shared_ptr<FakeDownloadManager> download_manager_;
    std::unique_ptr<service::FilesServiceImpl> service_;
};

// TC1: Valid capability allows authorized chunk download
TEST_F(FilesCapabilityIntegrationTest, TC1_ValidCapabilitySucceeds) {
    const std::string uid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
    const std::string did = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002";
    const std::string fid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003";

    std::string token = issue_token(uid, did, fid, FileCapabilityOperation::Read, 1);

    v1::DownloadChunkResponse resp;
    auto status = execute_download(fid, 0, uid, did, token, resp);

    EXPECT_TRUE(status.ok()) << status.error_message();
    EXPECT_EQ(resp.file_id(), fid);
    EXPECT_EQ(resp.chunk_index(), 0);
    EXPECT_EQ(resp.encrypted_data(), "ENCRYPTED_CIPHERTEXT_CHUNK_0");
    EXPECT_EQ(resp.ciphertext_sha256(), compute_sha256("ENCRYPTED_CIPHERTEXT_CHUNK_0"));
}

// TC2: Expired capability is rejected with PERMISSION_DENIED
TEST_F(FilesCapabilityIntegrationTest, TC2_ExpiredCapabilityRejected) {
    const std::string uid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
    const std::string did = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002";
    const std::string fid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003";

    // Expired TTL (negative TTL)
    std::string token = issue_token(uid, did, fid, FileCapabilityOperation::Read, 1, std::chrono::seconds(-60));

    v1::DownloadChunkResponse resp;
    auto status = execute_download(fid, 0, uid, did, token, resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    EXPECT_NE(status.error_message().find("expired"), std::string::npos);
}

// TC3: Wrong user (User A's capability presented by User B) is rejected
TEST_F(FilesCapabilityIntegrationTest, TC3_WrongUserRejected) {
    const std::string user_a = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
    const std::string user_b = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099";
    const std::string did = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002";
    const std::string fid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003";

    std::string token = issue_token(user_a, did, fid);

    v1::DownloadChunkResponse resp;
    auto status = execute_download(fid, 0, user_b, did, token, resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    EXPECT_NE(status.error_message().find("user mismatch"), std::string::npos);
}

// TC4: Wrong device (Device A's capability presented by Device B) is rejected
TEST_F(FilesCapabilityIntegrationTest, TC4_WrongDeviceRejected) {
    const std::string uid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
    const std::string dev_a = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002";
    const std::string dev_b = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099";
    const std::string fid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003";

    std::string token = issue_token(uid, dev_a, fid);

    v1::DownloadChunkResponse resp;
    auto status = execute_download(fid, 0, uid, dev_b, token, resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    EXPECT_NE(status.error_message().find("device mismatch"), std::string::npos);
}

// TC5: Wrong file (Capability for File 1 presented for File 2) is rejected
TEST_F(FilesCapabilityIntegrationTest, TC5_WrongFileRejected) {
    const std::string uid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
    const std::string did = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002";
    const std::string file_1 = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003";
    const std::string file_2 = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099";

    std::string token = issue_token(uid, did, file_1);

    v1::DownloadChunkResponse resp;
    auto status = execute_download(file_2, 0, uid, did, token, resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    EXPECT_NE(status.error_message().find("file mismatch"), std::string::npos);
}

// TC6: Wrong operation (Write capability presented for Download) is rejected
TEST_F(FilesCapabilityIntegrationTest, TC6_WrongOperationRejected) {
    const std::string uid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
    const std::string did = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002";
    const std::string fid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003";

    std::string token = issue_token(uid, did, fid, FileCapabilityOperation::Write);

    v1::DownloadChunkResponse resp;
    auto status = execute_download(fid, 0, uid, did, token, resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    EXPECT_NE(status.error_message().find("operation mismatch"), std::string::npos);
}

// TC7: Revoked device is rejected immediately
TEST_F(FilesCapabilityIntegrationTest, TC7_RevokedDeviceRejected) {
    const std::string uid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
    const std::string did = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002";
    const std::string fid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003";

    std::string token = issue_token(uid, did, fid, FileCapabilityOperation::Read);

    // Administrative device revocation occurs
    revocation_provider_->mark_device_revoked(did);

    v1::DownloadChunkResponse resp;
    auto status = execute_download(fid, 0, uid, did, token, resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    EXPECT_NE(status.error_message().find("revoked"), std::string::npos);
}

// TC8: Malformed capability is rejected with UNAUTHENTICATED
TEST_F(FilesCapabilityIntegrationTest, TC8_MalformedCapabilityRejected) {
    const std::string uid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
    const std::string did = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002";
    const std::string fid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003";

    v1::DownloadChunkResponse resp;
    auto status = execute_download(fid, 0, uid, did, "not.a.valid.signature", resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
}

// TC9: Replay outside allowed lifetime (premature token) is rejected
TEST_F(FilesCapabilityIntegrationTest, TC9_PrematureReplayRejected) {
    const std::string uid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
    const std::string did = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002";
    const std::string fid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003";

    auto now = std::chrono::system_clock::now();
    FileAccessCapabilityClaims claims{.capability_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000",
                                      .user_id = uid,
                                      .device_id = did,
                                      .file_id = fid,
                                      .file_version = 0,
                                      .operation = FileCapabilityOperation::Read,
                                      .issued_at = now + std::chrono::hours(1), // 1 hour in future
                                      .expires_at = now + std::chrono::hours(2),
                                      .issuer = "securecloud-files"};

    std::string token = FileCapabilitySerializer::serialize(claims, *signer_);

    v1::DownloadChunkResponse resp;
    auto status = execute_download(fid, 0, uid, did, token, resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
    EXPECT_NE(status.error_message().find("premature"), std::string::npos);
}

// TC10: Zero-decryption verification: content returned is raw ciphertext
TEST_F(FilesCapabilityIntegrationTest, TC10_ZeroDecryptionInvariant) {
    const std::string uid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
    const std::string did = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002";
    const std::string fid = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36003";

    std::string token = issue_token(uid, did, fid, FileCapabilityOperation::Read, 1);

    v1::DownloadChunkResponse resp;
    auto status = execute_download(fid, 1, uid, did, token, resp);

    EXPECT_TRUE(status.ok());
    // Verify ciphertext has NOT been decrypted or parsed into plaintext
    EXPECT_EQ(resp.encrypted_data(), "ENCRYPTED_CIPHERTEXT_CHUNK_1");
    EXPECT_EQ(resp.ciphertext_sha256(), compute_sha256("ENCRYPTED_CIPHERTEXT_CHUNK_1"));
}

} // namespace
} // namespace securecloud::files
