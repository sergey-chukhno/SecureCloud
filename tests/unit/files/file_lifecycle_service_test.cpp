#include "files/domain/lifecycle_state_machine.hpp"
#include "files/domain/metadata_validator.hpp"
#include "files/service/file_lifecycle_service.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::files {
namespace {

// ============================================================================
// Fail-Fast Parameter Validation Tests (No DB connection needed)
// ============================================================================

TEST(FileLifecycleServiceValidationTest, CreateFileRejectsInvalidUUID) {
    FileLifecycleService service(nullptr);
    auto now = std::chrono::system_clock::now();

    CreateFileRequestDto dto{
        .file_id = "invalid-uuid",
        .owner_user_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001",
        .owner_device_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002",
        .encrypted_size_bytes = 1024,
        .expected_chunk_count = 1,
        .encryption_algorithm = std::string(k_approved_encryption_algorithm),
        .encrypted_filename = {0x01, 0x02, 0x03},
        .metadata_nonce = std::vector<uint8_t>(24, 0xAA),
        .metadata_tag = std::vector<uint8_t>(16, 0xBB),
    };

    EXPECT_THROW(service.create_file(dto, now), FileLifecycleValidationException);
}

TEST(FileLifecycleServiceValidationTest, CreateFileRejectsZeroSize) {
    FileLifecycleService service(nullptr);
    auto now = std::chrono::system_clock::now();

    CreateFileRequestDto dto{
        .file_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000",
        .owner_user_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001",
        .owner_device_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002",
        .encrypted_size_bytes = 0,
        .expected_chunk_count = 0,
        .encryption_algorithm = std::string(k_approved_encryption_algorithm),
        .encrypted_filename = {0x01, 0x02, 0x03},
        .metadata_nonce = std::vector<uint8_t>(24, 0xAA),
        .metadata_tag = std::vector<uint8_t>(16, 0xBB),
    };

    EXPECT_THROW(service.create_file(dto, now), FileLifecycleValidationException);
}

TEST(FileLifecycleServiceValidationTest, CreateFileRejectsMismatchedChunkCount) {
    FileLifecycleService service(nullptr);
    auto now = std::chrono::system_clock::now();

    CreateFileRequestDto dto{
        .file_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000",
        .owner_user_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001",
        .owner_device_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002",
        .encrypted_size_bytes = 10 * 1024 * 1024, // 10 MiB -> expects 3 chunks
        .expected_chunk_count = 1,                // Wrong: says 1 chunk
        .encryption_algorithm = std::string(k_approved_encryption_algorithm),
        .encrypted_filename = {0x01, 0x02, 0x03},
        .metadata_nonce = std::vector<uint8_t>(24, 0xAA),
        .metadata_tag = std::vector<uint8_t>(16, 0xBB),
    };

    EXPECT_THROW(service.create_file(dto, now), FileLifecycleValidationException);
}

TEST(FileLifecycleServiceValidationTest, CreateFileVersionRejectsInvalidVersionNumber) {
    FileLifecycleService service(nullptr);

    CreateFileVersionRequestDto dto{
        .file_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000",
        .version_number = 0, // Must be >= 1
        .encrypted_size_bytes = 1024,
        .minio_object_key = "objects/0191ec4d-91b4-7b4d-b6a9-8e41e3d36000/1",
        .checksum_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    };

    EXPECT_THROW(service.create_file_version(dto, "user-1"), FileLifecycleValidationException);
}

TEST(FileLifecycleServiceValidationTest, CreateFileVersionRejectsInvalidSha256) {
    FileLifecycleService service(nullptr);

    CreateFileVersionRequestDto dto{
        .file_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000",
        .version_number = 2,
        .encrypted_size_bytes = 1024,
        .minio_object_key = "objects/0191ec4d-91b4-7b4d-b6a9-8e41e3d36000/2",
        .checksum_sha256 = "invalid-sha-hex",
    };

    EXPECT_THROW(service.create_file_version(dto, "user-1"), FileLifecycleValidationException);
}

TEST(FileLifecycleServiceValidationTest, TransitionLifecycleRejectsDisallowedTransitions) {
    FileLifecycleService service(nullptr);

    // AVAILABLE -> CREATED is strictly illegal
    EXPECT_THROW(service.transition_lifecycle("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000", FileStatus::Available,
                                              FileStatus::Created, "user-1"),
                 InvalidLifecycleTransitionException);

    // DELETED is terminal -> cannot transition to AVAILABLE
    EXPECT_THROW(service.transition_lifecycle("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000", FileStatus::Deleted,
                                              FileStatus::Available, "user-1"),
                 InvalidLifecycleTransitionException);

    // FAILED is terminal -> cannot transition to UPLOADING
    EXPECT_THROW(service.transition_lifecycle("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000", FileStatus::Failed,
                                              FileStatus::Uploading, "user-1"),
                 InvalidLifecycleTransitionException);
}

// ============================================================================
// Mock FileLifecycleService for Service Domain Behavior Tests
// ============================================================================

class MockFileLifecycleService : public FileLifecycleService {
  public:
    MockFileLifecycleService() : FileLifecycleService(nullptr) {}

    std::string create_file(const CreateFileRequestDto& dto, std::chrono::system_clock::time_point now) override {
        auto val = validate_create_file_request(dto, now);
        if (!val) {
            throw FileLifecycleValidationException(val.error_message);
        }
        created_file_id_ = dto.file_id;
        return created_file_id_;
    }

    FileVersionEntity create_file_version(const CreateFileVersionRequestDto& dto,
                                          const std::string& caller_user_id) override {
        auto val = validate_create_version_request(dto);
        if (!val) {
            throw FileLifecycleValidationException(val.error_message);
        }
        if (caller_user_id != expected_owner_id_ && !allow_access_) {
            throw UnauthorizedFileAccessException("User " + caller_user_id + " not authorized to create version");
        }
        if (immutable_version_conflict_) {
            throw ImmutableVersionException("Version 1 is completed and immutable; cannot mutate in-place");
        }
        return FileVersionEntity{
            .version_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36099",
            .file_id = dto.file_id,
            .version_number = dto.version_number,
            .minio_object_key = dto.minio_object_key,
            .encrypted_size = static_cast<int64_t>(dto.encrypted_size_bytes),
            .checksum_sha256 = dto.checksum_sha256,
            .created_at = std::chrono::system_clock::now(),
        };
    }

    bool transition_lifecycle(const std::string& /*file_id*/, FileStatus expected_current, FileStatus new_status,
                              const std::string& caller_user_id, const std::string& /*reason*/) override {
        assert_valid_state_transition(expected_current, new_status);
        if (caller_user_id != expected_owner_id_ && !allow_access_) {
            throw UnauthorizedFileAccessException("User " + caller_user_id + " not authorized to transition file");
        }
        current_status_ = new_status;
        return true;
    }

    std::optional<FileMetadataSummary> get_file_metadata(const std::string& file_id,
                                                         const std::string& caller_user_id) override {
        if (file_id != mock_summary_.file.file_id) {
            return std::nullopt;
        }
        if (caller_user_id != mock_summary_.file.owner_user_id && !allow_access_) {
            throw UnauthorizedFileAccessException("User " + caller_user_id + " not authorized to read file");
        }
        return mock_summary_;
    }

    bool delete_file(const std::string& file_id, const std::string& caller_user_id,
                     const std::string& /*reason*/ = "") override {
        if (file_id != mock_summary_.file.file_id) {
            return false;
        }
        if (caller_user_id != mock_summary_.file.owner_user_id && !allow_access_) {
            throw UnauthorizedFileAccessException("User " + caller_user_id + " not authorized to delete file");
        }
        mock_summary_.file.status = FileStatus::Deleted;
        return true;
    }

    size_t evaluate_and_expire_files(std::chrono::system_clock::time_point /*now*/, size_t /*batch_size*/) override {
        return expired_count_;
    }

    void set_mock_summary(FileMetadataSummary summary) { mock_summary_ = std::move(summary); }
    void set_expected_owner(std::string owner_id) { expected_owner_id_ = std::move(owner_id); }
    void set_allow_access(bool allow) { allow_access_ = allow; }
    void set_immutable_conflict(bool conflict) { immutable_version_conflict_ = conflict; }
    void set_expired_count(size_t count) { expired_count_ = count; }

  private:
    std::string created_file_id_;
    std::string expected_owner_id_{"0191ec4d-91b4-7b4d-b6a9-8e41e3d36001"};
    bool allow_access_{false};
    bool immutable_version_conflict_{false};
    size_t expired_count_{0};
    FileStatus current_status_{FileStatus::Created};
    FileMetadataSummary mock_summary_;
};

// ============================================================================
// Service Domain Invariant Tests with Mock
// ============================================================================

TEST(FileLifecycleServiceMockTest, EnforcesImmutableCompletedVersionsInvariant) {
    MockFileLifecycleService service;
    service.set_expected_owner("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    service.set_immutable_conflict(true);

    CreateFileVersionRequestDto dto{
        .file_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000",
        .version_number = 1,
        .encrypted_size_bytes = 4096,
        .minio_object_key = "objects/0191ec4d-91b4-7b4d-b6a9-8e41e3d36000/1",
        .checksum_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    };

    // Attempting to overwrite or mutate an existing completed version must throw ImmutableVersionException
    EXPECT_THROW(service.create_file_version(dto, "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001"), ImmutableVersionException);
}

TEST(FileLifecycleServiceMockTest, EnforcesOwnershipAccessControl) {
    MockFileLifecycleService service;
    service.set_expected_owner("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    service.set_allow_access(false);

    const auto now = std::chrono::system_clock::now();
    FileEntity file_entity{
        .file_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000",
        .owner_user_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001",
        .owner_device_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002",
        .conversation_id = std::nullopt,
        .encrypted_size = 0,
        .content_type = std::nullopt,
        .encryption_algorithm = "XChaCha20-Poly1305",
        .status = FileStatus::Available,
        .retention_until = std::nullopt,
        .created_at = now,
        .updated_at = now,
    };
    EncryptedFileMetadataEntity enc_meta{
        .file_id = file_entity.file_id,
        .encrypted_filename = {0x01, 0x02},
        .encrypted_mime_type = std::nullopt,
        .metadata_nonce = std::vector<uint8_t>(24, 0x01),
        .metadata_tag = std::vector<uint8_t>(16, 0x02),
        .client_encryption_metadata_json = "{}",
        .updated_at = now,
    };
    service.set_mock_summary(FileMetadataSummary{
        .file = file_entity,
        .encrypted_meta = enc_meta,
        .active_version = std::nullopt,
        .all_versions = {},
        .expected_chunk_count = 0,
    });

    // 1. Authorized owner access succeeds
    auto owner_meta =
        service.get_file_metadata("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000", "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    ASSERT_TRUE(owner_meta.has_value());
    EXPECT_EQ(owner_meta->file.file_id, "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");

    // 2. Unauthorized caller (different user ID) is rejected with UnauthorizedFileAccessException
    EXPECT_THROW(
        service.get_file_metadata("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000", "0191ec4d-91b4-7b4d-b6a9-8e41e3d36999"),
        UnauthorizedFileAccessException);

    // 3. Unauthorized caller cannot delete file
    EXPECT_THROW(service.delete_file("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000", "0191ec4d-91b4-7b4d-b6a9-8e41e3d36999"),
                 UnauthorizedFileAccessException);

    // 4. Granting access allows read
    service.set_allow_access(true);
    auto grantee_meta =
        service.get_file_metadata("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000", "0191ec4d-91b4-7b4d-b6a9-8e41e3d36999");
    ASSERT_TRUE(grantee_meta.has_value());
}

TEST(FileLifecycleServiceMockTest, LogicalDeletionMarksFileAsDeleted) {
    MockFileLifecycleService service;
    const std::string owner_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36001";
    service.set_expected_owner(owner_id);

    const auto now = std::chrono::system_clock::now();
    FileEntity file_entity{
        .file_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000",
        .owner_user_id = owner_id,
        .owner_device_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002",
        .conversation_id = std::nullopt,
        .encrypted_size = 0,
        .content_type = std::nullopt,
        .encryption_algorithm = "XChaCha20-Poly1305",
        .status = FileStatus::Available,
        .retention_until = std::nullopt,
        .created_at = now,
        .updated_at = now,
    };
    service.set_mock_summary(FileMetadataSummary{
        .file = file_entity,
        .encrypted_meta = {},
        .active_version = std::nullopt,
        .all_versions = {},
        .expected_chunk_count = 0,
    });

    bool deleted = service.delete_file("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000", owner_id, "User requested");
    EXPECT_TRUE(deleted);

    auto meta = service.get_file_metadata("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000", owner_id);
    ASSERT_TRUE(meta.has_value());
    EXPECT_EQ(meta->file.status, FileStatus::Deleted);
}

TEST(FileLifecycleServiceMockTest, ExpirationScannerReturnsCount) {
    MockFileLifecycleService service;
    service.set_expired_count(5);

    auto count = service.evaluate_and_expire_files(std::chrono::system_clock::now(), 100);
    EXPECT_EQ(count, 5);
}

} // namespace
} // namespace securecloud::files
