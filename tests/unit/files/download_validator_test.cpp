#include "files/domain/download_validator.hpp"
#include "files/domain/lifecycle_state_machine.hpp"

#include <gtest/gtest.h>

namespace securecloud::files {
namespace {

TEST(DownloadValidatorTest, CalculateByteRangeSingleSmallChunk) {
    auto range_opt = calculate_chunk_byte_range(1000, 0);
    ASSERT_TRUE(range_opt.has_value());
    EXPECT_EQ(range_opt->start_byte, 0);
    EXPECT_EQ(range_opt->end_byte, 999);
    EXPECT_EQ(range_opt->chunk_size_bytes, 1000);
    EXPECT_EQ(range_opt->total_chunks, 1);

    // chunk 1 is out of bounds
    EXPECT_FALSE(calculate_chunk_byte_range(1000, 1).has_value());
}

TEST(DownloadValidatorTest, CalculateByteRangeExactMultiples) {
    // 8 MiB = 2 exact chunks of 4 MiB (4194304 bytes each)
    uint64_t total_size = 8ULL * 1024ULL * 1024ULL;

    auto c0 = calculate_chunk_byte_range(total_size, 0);
    ASSERT_TRUE(c0.has_value());
    EXPECT_EQ(c0->start_byte, 0);
    EXPECT_EQ(c0->end_byte, 4194303);
    EXPECT_EQ(c0->chunk_size_bytes, 4194304);
    EXPECT_EQ(c0->total_chunks, 2);

    auto c1 = calculate_chunk_byte_range(total_size, 1);
    ASSERT_TRUE(c1.has_value());
    EXPECT_EQ(c1->start_byte, 4194304);
    EXPECT_EQ(c1->end_byte, 8388607);
    EXPECT_EQ(c1->chunk_size_bytes, 4194304);
    EXPECT_EQ(c1->total_chunks, 2);

    EXPECT_FALSE(calculate_chunk_byte_range(total_size, 2).has_value());
}

TEST(DownloadValidatorTest, CalculateByteRangePartialTrailingChunk) {
    // 5 MiB = 1 standard 4 MiB chunk + 1 partial 1 MiB chunk
    uint64_t total_size = 5ULL * 1024ULL * 1024ULL;

    auto c0 = calculate_chunk_byte_range(total_size, 0);
    ASSERT_TRUE(c0.has_value());
    EXPECT_EQ(c0->start_byte, 0);
    EXPECT_EQ(c0->end_byte, 4194303);
    EXPECT_EQ(c0->chunk_size_bytes, 4194304);
    EXPECT_EQ(c0->total_chunks, 2);

    auto c1 = calculate_chunk_byte_range(total_size, 1);
    ASSERT_TRUE(c1.has_value());
    EXPECT_EQ(c1->start_byte, 4194304);
    EXPECT_EQ(c1->end_byte, 5242879);
    EXPECT_EQ(c1->chunk_size_bytes, 1048576);
    EXPECT_EQ(c1->total_chunks, 2);
}

TEST(DownloadValidatorTest, CalculateByteRangeZeroSizeFile) {
    auto c0 = calculate_chunk_byte_range(0, 0);
    ASSERT_TRUE(c0.has_value());
    EXPECT_EQ(c0->start_byte, 0);
    EXPECT_EQ(c0->end_byte, 0);
    EXPECT_EQ(c0->chunk_size_bytes, 0);
    EXPECT_EQ(c0->total_chunks, 0);

    EXPECT_FALSE(calculate_chunk_byte_range(0, 1).has_value());
}

FileEntity make_test_file(std::string file_id = "018f6e80-7b23-74d1-81f8-000000000001",
                          FileStatus status = FileStatus::Available, std::string owner = "user-alice",
                          uint64_t size = 1000) {
    FileEntity f;
    f.file_id = std::move(file_id);
    f.owner_user_id = std::move(owner);
    f.status = status;
    f.encrypted_size = static_cast<int64_t>(size);
    return f;
}

FileVersionEntity make_test_version(std::string file_id = "018f6e80-7b23-74d1-81f8-000000000001",
                                    int32_t version_number = 1, uint64_t size = 1000) {
    FileVersionEntity v;
    v.version_id = "018f6e80-7b23-74d1-81f8-000000000002";
    v.file_id = std::move(file_id);
    v.version_number = version_number;
    v.encrypted_size = static_cast<int64_t>(size);
    v.minio_object_key = "objects/" + v.file_id + "/" + std::to_string(version_number);
    v.checksum_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    v.is_active = true;
    return v;
}

TEST(DownloadValidatorTest, ValidPreconditionsOwner) {
    DownloadValidationInput input{
        .file_id = "018f6e80-7b23-74d1-81f8-000000000001",
        .requested_version = 0,
        .chunk_index = 0,
        .file = make_test_file(),
        .version = make_test_version(),
        .caller_user_id = "user-alice",
        .has_read_permission = false // Owner is implicitly permitted
    };

    auto res = validate_download_preconditions(input);
    EXPECT_TRUE(res.is_valid);
    EXPECT_TRUE(res.error_message.empty());
}

TEST(DownloadValidatorTest, ValidPreconditionsGranteeWithReadPermission) {
    DownloadValidationInput input{
        .file_id = "018f6e80-7b23-74d1-81f8-000000000001",
        .requested_version = 1,
        .chunk_index = 0,
        .file = make_test_file("018f6e80-7b23-74d1-81f8-000000000001", FileStatus::Available, "user-alice"),
        .version = make_test_version("018f6e80-7b23-74d1-81f8-000000000001", 1),
        .caller_user_id = "user-bob",
        .has_read_permission = true};

    auto res = validate_download_preconditions(input);
    EXPECT_TRUE(res.is_valid);
}

TEST(DownloadValidatorTest, RejectInvalidFileId) {
    DownloadValidationInput input{.file_id = "bad-uuid",
                                  .requested_version = 0,
                                  .chunk_index = 0,
                                  .file = make_test_file("bad-uuid"),
                                  .version = make_test_version("bad-uuid"),
                                  .caller_user_id = "user-alice",
                                  .has_read_permission = true};

    auto res = validate_download_preconditions(input);
    EXPECT_FALSE(res.is_valid);
    EXPECT_NE(res.error_message.find("Invalid file_id format"), std::string::npos);
}

TEST(DownloadValidatorTest, RejectUnauthorizedUser) {
    DownloadValidationInput input{
        .file_id = "018f6e80-7b23-74d1-81f8-000000000001",
        .requested_version = 0,
        .chunk_index = 0,
        .file = make_test_file("018f6e80-7b23-74d1-81f8-000000000001", FileStatus::Available, "user-alice"),
        .version = make_test_version(),
        .caller_user_id = "user-eve",
        .has_read_permission = false};

    auto res = validate_download_preconditions(input);
    EXPECT_FALSE(res.is_valid);
    EXPECT_NE(res.error_message.find("lacks READ authorization"), std::string::npos);
}

TEST(DownloadValidatorTest, RejectUnavailableFileState) {
    auto file = make_test_file();
    file.status = FileStatus::Uploading;

    DownloadValidationInput input{.file_id = "018f6e80-7b23-74d1-81f8-000000000001",
                                  .requested_version = 0,
                                  .chunk_index = 0,
                                  .file = file,
                                  .version = make_test_version(),
                                  .caller_user_id = "user-alice",
                                  .has_read_permission = true};

    auto res = validate_download_preconditions(input);
    EXPECT_FALSE(res.is_valid);
    EXPECT_NE(res.error_message.find("not available for download"), std::string::npos);

    file.status = FileStatus::Deleted;
    input.file = file;
    res = validate_download_preconditions(input);
    EXPECT_FALSE(res.is_valid);
    EXPECT_NE(res.error_message.find("DELETED"), std::string::npos);
}

TEST(DownloadValidatorTest, RejectMissingVersionSnapshot) {
    DownloadValidationInput input{.file_id = "018f6e80-7b23-74d1-81f8-000000000001",
                                  .requested_version = 0,
                                  .chunk_index = 0,
                                  .file = make_test_file(),
                                  .version = std::nullopt,
                                  .caller_user_id = "user-alice",
                                  .has_read_permission = true};

    auto res = validate_download_preconditions(input);
    EXPECT_FALSE(res.is_valid);
    EXPECT_NE(res.error_message.find("version snapshot not found"), std::string::npos);
}

TEST(DownloadValidatorTest, RejectVersionMismatch) {
    DownloadValidationInput input{.file_id = "018f6e80-7b23-74d1-81f8-000000000001",
                                  .requested_version = 2, // Requested v2, but only v1 exists
                                  .chunk_index = 0,
                                  .file = make_test_file(),
                                  .version = make_test_version("018f6e80-7b23-74d1-81f8-000000000001", 1),
                                  .caller_user_id = "user-alice",
                                  .has_read_permission = true};

    auto res = validate_download_preconditions(input);
    EXPECT_FALSE(res.is_valid);
    EXPECT_NE(res.error_message.find("does not match retrieved snapshot version"), std::string::npos);
}

TEST(DownloadValidatorTest, RejectOutOfBoundsChunkIndex) {
    DownloadValidationInput input{.file_id = "018f6e80-7b23-74d1-81f8-000000000001",
                                  .requested_version = 0,
                                  .chunk_index = 5, // File has size 1000, so only 1 chunk (index 0)
                                  .file = make_test_file(),
                                  .version = make_test_version(),
                                  .caller_user_id = "user-alice",
                                  .has_read_permission = true};

    auto res = validate_download_preconditions(input);
    EXPECT_FALSE(res.is_valid);
    EXPECT_NE(res.error_message.find("out of bounds"), std::string::npos);
}

} // namespace
} // namespace securecloud::files
