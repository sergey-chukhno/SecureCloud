#include "files/domain/finalization_validator.hpp"
#include "files/domain/chunk_validator.hpp"

#include <gtest/gtest.h>

namespace securecloud::files {
namespace {

FileTransferEntity make_test_transfer(std::string transfer_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e",
                                     TransferStatus status = TransferStatus::Transferring,
                                     uint32_t total_chunks = 2,
                                     uint32_t accepted_chunks = 2,
                                     uint64_t total_bytes = 1000) {
    FileTransferEntity t;
    t.transfer_id = std::move(transfer_id);
    t.file_id = "018f6e80-7b23-74d1-81f8-000000000001";
    t.transfer_type = TransferType::Upload;
    t.status = status;
    t.total_bytes = total_bytes;
    t.transferred_bytes = total_bytes;
    t.total_chunks = total_chunks;
    t.accepted_chunks = accepted_chunks;
    return t;
}

FileEntity make_test_file(std::string file_id = "018f6e80-7b23-74d1-81f8-000000000001",
                          FileStatus status = FileStatus::Uploading,
                          uint64_t encrypted_size = 1000) {
    FileEntity f;
    f.file_id = std::move(file_id);
    f.owner_user_id = "user-123";
    f.owner_device_id = "dev-123";
    f.status = status;
    f.encrypted_size = encrypted_size;
    f.expected_chunk_count = 2;
    return f;
}

std::vector<FileChunkEntity> make_test_chunks(const std::string& transfer_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e") {
    FileChunkEntity c0;
    c0.transfer_id = transfer_id;
    c0.chunk_index = 0;
    c0.chunk_size = 600;
    c0.chunk_hash_sha256 = compute_sha256_hex("chunk0");
    c0.minio_chunk_key = "staging/" + transfer_id + "/0";

    FileChunkEntity c1;
    c1.transfer_id = transfer_id;
    c1.chunk_index = 1;
    c1.chunk_size = 400;
    c1.chunk_hash_sha256 = compute_sha256_hex("chunk1");
    c1.minio_chunk_key = "staging/" + transfer_id + "/1";

    return {c0, c1};
}

TEST(FinalizationValidatorTest, ValidPreconditionsMultiChunk) {
    FinalizationValidationInput input{
        .transfer = make_test_transfer(),
        .file = make_test_file(),
        .chunks = make_test_chunks(),
        .expected_ciphertext_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    };

    auto res = validate_finalization_preconditions(input);
    EXPECT_TRUE(res.is_valid);
    EXPECT_TRUE(res.error_message.empty());
}

TEST(FinalizationValidatorTest, ValidPreconditionsUnorderedChunksAreSorted) {
    auto chunks = make_test_chunks();
    std::reverse(chunks.begin(), chunks.end()); // Pass in reverse order

    FinalizationValidationInput input{
        .transfer = make_test_transfer(),
        .file = make_test_file(),
        .chunks = chunks,
        .expected_ciphertext_sha256 = ""
    };

    auto res = validate_finalization_preconditions(input);
    EXPECT_TRUE(res.is_valid);
}

TEST(FinalizationValidatorTest, RejectEmptyTransferId) {
    FinalizationValidationInput input{
        .transfer = make_test_transfer(""),
        .file = make_test_file(),
        .chunks = make_test_chunks(),
        .expected_ciphertext_sha256 = ""
    };

    auto res = validate_finalization_preconditions(input);
    EXPECT_FALSE(res.is_valid);
    EXPECT_NE(res.error_message.find("Transfer ID must not be empty"), std::string::npos);
}

TEST(FinalizationValidatorTest, RejectCancelledOrExpiredTransfer) {
    auto transfer = make_test_transfer();
    transfer.status = TransferStatus::Cancelled;

    FinalizationValidationInput input{
        .transfer = transfer,
        .file = make_test_file(),
        .chunks = make_test_chunks(),
        .expected_ciphertext_sha256 = ""
    };

    auto res = validate_finalization_preconditions(input);
    EXPECT_FALSE(res.is_valid);
    EXPECT_NE(res.error_message.find("cancelled"), std::string::npos);

    transfer.status = TransferStatus::Expired;
    input.transfer = transfer;
    res = validate_finalization_preconditions(input);
    EXPECT_FALSE(res.is_valid);
    EXPECT_NE(res.error_message.find("expired"), std::string::npos);

    transfer.status = TransferStatus::Failed;
    input.transfer = transfer;
    res = validate_finalization_preconditions(input);
    EXPECT_FALSE(res.is_valid);
    EXPECT_NE(res.error_message.find("failed"), std::string::npos);
}

TEST(FinalizationValidatorTest, RejectDeletedOrExpiredFile) {
    auto file = make_test_file();
    file.status = FileStatus::Deleted;

    FinalizationValidationInput input{
        .transfer = make_test_transfer(),
        .file = file,
        .chunks = make_test_chunks(),
        .expected_ciphertext_sha256 = ""
    };

    auto res = validate_finalization_preconditions(input);
    EXPECT_FALSE(res.is_valid);
    EXPECT_NE(res.error_message.find("deleted"), std::string::npos);

    file.status = FileStatus::Expired;
    input.file = file;
    res = validate_finalization_preconditions(input);
    EXPECT_FALSE(res.is_valid);
    EXPECT_NE(res.error_message.find("expired"), std::string::npos);
}

TEST(FinalizationValidatorTest, RejectChunkCountMismatch) {
    auto transfer = make_test_transfer();
    transfer.total_chunks = 3;
    transfer.accepted_chunks = 2; // only 2 accepted

    FinalizationValidationInput input{
        .transfer = transfer,
        .file = make_test_file(),
        .chunks = make_test_chunks(), // 2 chunks
        .expected_ciphertext_sha256 = ""
    };

    auto res = validate_finalization_preconditions(input);
    EXPECT_FALSE(res.is_valid);
    EXPECT_NE(res.error_message.find("Chunk count mismatch"), std::string::npos);
}

TEST(FinalizationValidatorTest, RejectMissingGappedChunkIndex) {
    auto chunks = make_test_chunks();
    chunks[1].chunk_index = 2; // indices are 0 and 2, missing 1

    FinalizationValidationInput input{
        .transfer = make_test_transfer(),
        .file = make_test_file(),
        .chunks = chunks,
        .expected_ciphertext_sha256 = ""
    };

    auto res = validate_finalization_preconditions(input);
    EXPECT_FALSE(res.is_valid);
    EXPECT_NE(res.error_message.find("Missing chunk at index 1"), std::string::npos);
}

TEST(FinalizationValidatorTest, RejectEmptyStorageKeyOrInvalidHash) {
    auto chunks = make_test_chunks();
    chunks[0].minio_chunk_key = ""; // missing key

    FinalizationValidationInput input{
        .transfer = make_test_transfer(),
        .file = make_test_file(),
        .chunks = chunks,
        .expected_ciphertext_sha256 = ""
    };

    auto res = validate_finalization_preconditions(input);
    EXPECT_FALSE(res.is_valid);
    EXPECT_NE(res.error_message.find("missing or empty storage key"), std::string::npos);

    chunks = make_test_chunks();
    chunks[1].chunk_hash_sha256 = "invalid-not-sha256";
    input.chunks = chunks;

    res = validate_finalization_preconditions(input);
    EXPECT_FALSE(res.is_valid);
    EXPECT_NE(res.error_message.find("invalid SHA-256 digest format"), std::string::npos);
}

TEST(FinalizationValidatorTest, RejectChunkSizeSumMismatch) {
    auto chunks = make_test_chunks();
    chunks[1].chunk_size = 500; // sum is 600 + 500 = 1100, but transfer is 1000

    FinalizationValidationInput input{
        .transfer = make_test_transfer(),
        .file = make_test_file(),
        .chunks = chunks,
        .expected_ciphertext_sha256 = ""
    };

    auto res = validate_finalization_preconditions(input);
    EXPECT_FALSE(res.is_valid);
    EXPECT_NE(res.error_message.find("Cumulative chunk byte size mismatch"), std::string::npos);
}

TEST(FinalizationValidatorTest, RejectInvalidExpectedCiphertextSha256) {
    FinalizationValidationInput input{
        .transfer = make_test_transfer(),
        .file = make_test_file(),
        .chunks = make_test_chunks(),
        .expected_ciphertext_sha256 = "not-64-hex-characters"
    };

    auto res = validate_finalization_preconditions(input);
    EXPECT_FALSE(res.is_valid);
    EXPECT_NE(res.error_message.find("expected_ciphertext_sha256 is not a valid 64-character hex string"),
              std::string::npos);
}

} // namespace
} // namespace securecloud::files
