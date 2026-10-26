#include "files/domain/chunk_validator.hpp"

#include <gtest/gtest.h>

namespace securecloud::files {
namespace {

TEST(ChunkValidatorTest, ComputeSha256KnownVectors) {
    EXPECT_EQ(compute_sha256_hex(""),
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_EQ(compute_sha256_hex("hello"),
              "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}

TEST(ChunkValidatorTest, ValidSingleChunkFilePayload) {
    std::string payload = "Encrypted ciphertext content representing a single small file";
    std::string hash = compute_sha256_hex(payload);

    ChunkPayloadDto dto{
        .upload_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e",
        .chunk_index = 0,
        .encrypted_data = payload,
        .chunk_size_bytes = static_cast<uint32_t>(payload.size()),
        .claimed_sha256 = hash,
    };

    auto result = validate_chunk_payload(dto, 1, payload.size());
    EXPECT_TRUE(result.is_valid);
    EXPECT_TRUE(result.error_message.empty());
    EXPECT_EQ(result.computed_sha256, hash);
}

TEST(ChunkValidatorTest, CaseInsensitiveSha256Verification) {
    std::string payload = "Test case insensitivity";
    std::string hash = compute_sha256_hex(payload);
    std::string upper_hash = hash;
    for (char& c : upper_hash) {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }

    ChunkPayloadDto dto{
        .upload_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e",
        .chunk_index = 0,
        .encrypted_data = payload,
        .chunk_size_bytes = static_cast<uint32_t>(payload.size()),
        .claimed_sha256 = upper_hash,
    };

    auto result = validate_chunk_payload(dto, 1, payload.size());
    EXPECT_TRUE(result.is_valid);
    EXPECT_EQ(result.computed_sha256, hash);
}

TEST(ChunkValidatorTest, RejectInvalidUploadId) {
    std::string payload = "data";
    ChunkPayloadDto dto{
        .upload_id = "not-a-valid-uuid",
        .chunk_index = 0,
        .encrypted_data = payload,
        .chunk_size_bytes = static_cast<uint32_t>(payload.size()),
        .claimed_sha256 = compute_sha256_hex(payload),
    };

    auto result = validate_chunk_payload(dto, 1, payload.size());
    EXPECT_FALSE(result.is_valid);
    EXPECT_NE(result.error_message.find("upload_id"), std::string::npos);
}

TEST(ChunkValidatorTest, RejectZeroTotalChunks) {
    std::string payload = "data";
    ChunkPayloadDto dto{
        .upload_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e",
        .chunk_index = 0,
        .encrypted_data = payload,
        .chunk_size_bytes = static_cast<uint32_t>(payload.size()),
        .claimed_sha256 = compute_sha256_hex(payload),
    };

    auto result = validate_chunk_payload(dto, 0, payload.size());
    EXPECT_FALSE(result.is_valid);
    EXPECT_NE(result.error_message.find("total_chunks"), std::string::npos);
}

TEST(ChunkValidatorTest, RejectOutOfBoundsChunkIndex) {
    std::string payload = "data";
    ChunkPayloadDto dto{
        .upload_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e",
        .chunk_index = 2,
        .encrypted_data = payload,
        .chunk_size_bytes = static_cast<uint32_t>(payload.size()),
        .claimed_sha256 = compute_sha256_hex(payload),
    };

    auto result = validate_chunk_payload(dto, 2, 8U * 1024U * 1024U);
    EXPECT_FALSE(result.is_valid);
    EXPECT_NE(result.error_message.find("out of bounds"), std::string::npos);
}

TEST(ChunkValidatorTest, RejectPayloadSizeMismatch) {
    std::string payload = "real content";
    ChunkPayloadDto dto{
        .upload_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e",
        .chunk_index = 0,
        .encrypted_data = payload,
        .chunk_size_bytes = static_cast<uint32_t>(payload.size() + 10),
        .claimed_sha256 = compute_sha256_hex(payload),
    };

    auto result = validate_chunk_payload(dto, 1, payload.size());
    EXPECT_FALSE(result.is_valid);
    EXPECT_NE(result.error_message.find("does not match"), std::string::npos);
}

TEST(ChunkValidatorTest, RejectEmptyChunkPayload) {
    std::string payload = "";
    ChunkPayloadDto dto{
        .upload_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e",
        .chunk_index = 0,
        .encrypted_data = payload,
        .chunk_size_bytes = 0,
        .claimed_sha256 = compute_sha256_hex(payload),
    };

    auto result = validate_chunk_payload(dto, 1, 0);
    EXPECT_FALSE(result.is_valid);
    EXPECT_NE(result.error_message.find("at least 1 byte"), std::string::npos);
}

TEST(ChunkValidatorTest, RejectOversizedChunk) {
    // 8 MiB + 1 byte
    std::string payload(k_max_chunk_size + 1, 'x');
    ChunkPayloadDto dto{
        .upload_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e",
        .chunk_index = 0,
        .encrypted_data = payload,
        .chunk_size_bytes = static_cast<uint32_t>(payload.size()),
        .claimed_sha256 = compute_sha256_hex(payload),
    };

    auto result = validate_chunk_payload(dto, 1, payload.size());
    EXPECT_FALSE(result.is_valid);
    EXPECT_NE(result.error_message.find("exceeds maximum allowed chunk size"), std::string::npos);
}

TEST(ChunkValidatorTest, NonTerminalChunkMustBeStandardSize) {
    // Non-terminal chunk of 2 MiB in a 2-chunk file (total 6 MiB)
    std::string payload(2U * 1024U * 1024U, 'a');
    ChunkPayloadDto dto{
        .upload_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e",
        .chunk_index = 0,
        .encrypted_data = payload,
        .chunk_size_bytes = static_cast<uint32_t>(payload.size()),
        .claimed_sha256 = compute_sha256_hex(payload),
    };

    auto result = validate_chunk_payload(dto, 2, 6ULL * 1024ULL * 1024ULL);
    EXPECT_FALSE(result.is_valid);
    EXPECT_NE(result.error_message.find("Non-terminal chunk"), std::string::npos);
}

TEST(ChunkValidatorTest, TerminalChunkSizeMustMatchRemainingBytes) {
    // Total file 6 MiB = chunk 0 (4 MiB) + chunk 1 (2 MiB)
    std::string terminal_payload(1U * 1024U * 1024U, 'b'); // only 1 MiB instead of 2 MiB
    ChunkPayloadDto dto{
        .upload_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e",
        .chunk_index = 1,
        .encrypted_data = terminal_payload,
        .chunk_size_bytes = static_cast<uint32_t>(terminal_payload.size()),
        .claimed_sha256 = compute_sha256_hex(terminal_payload),
    };

    auto result = validate_chunk_payload(dto, 2, 6ULL * 1024ULL * 1024ULL);
    EXPECT_FALSE(result.is_valid);
    EXPECT_NE(result.error_message.find("Terminal chunk"), std::string::npos);
}

TEST(ChunkValidatorTest, RejectMalformedSha256HexFormat) {
    std::string payload = "data";
    ChunkPayloadDto dto{
        .upload_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e",
        .chunk_index = 0,
        .encrypted_data = payload,
        .chunk_size_bytes = static_cast<uint32_t>(payload.size()),
        .claimed_sha256 = "tooshortsha256",
    };

    auto result = validate_chunk_payload(dto, 1, payload.size());
    EXPECT_FALSE(result.is_valid);
    EXPECT_NE(result.error_message.find("claimed_sha256"), std::string::npos);
}

TEST(ChunkValidatorTest, RejectDigestMismatch) {
    std::string payload = "valid data";
    std::string actual_hash = compute_sha256_hex(payload);
    std::string fake_hash = compute_sha256_hex("different data");

    ChunkPayloadDto dto{
        .upload_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e",
        .chunk_index = 0,
        .encrypted_data = payload,
        .chunk_size_bytes = static_cast<uint32_t>(payload.size()),
        .claimed_sha256 = fake_hash,
    };

    auto result = validate_chunk_payload(dto, 1, payload.size());
    EXPECT_FALSE(result.is_valid);
    EXPECT_NE(result.error_message.find("SHA-256 digest mismatch"), std::string::npos);
    EXPECT_EQ(result.computed_sha256, actual_hash);
}

} // namespace
} // namespace securecloud::files
