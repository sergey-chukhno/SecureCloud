#include "files/domain/metadata_validator.hpp"

#include <chrono>
#include <gtest/gtest.h>

namespace securecloud::files {
namespace {

TEST(MetadataValidatorTest, IsValidUuid) {
    EXPECT_TRUE(is_valid_uuid("0191ec4d-9a6a-7d9a-9e58-69315570c634"));
    EXPECT_TRUE(is_valid_uuid("00000000-0000-0000-0000-000000000000"));
    EXPECT_TRUE(is_valid_uuid("ffffffff-ffff-ffff-ffff-ffffffffffff"));
    EXPECT_TRUE(is_valid_uuid("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"));

    // Invalid length
    EXPECT_FALSE(is_valid_uuid("0191ec4d-9a6a-7d9a-9e58-69315570c63"));
    EXPECT_FALSE(is_valid_uuid("0191ec4d-9a6a-7d9a-9e58-69315570c6345"));
    EXPECT_FALSE(is_valid_uuid(""));

    // Missing or misplaced hyphens
    EXPECT_FALSE(is_valid_uuid("0191ec4d9a6a7d9a9e5869315570c6340000"));
    EXPECT_FALSE(is_valid_uuid("0191ec4d-9a6a7-d9a-9e58-69315570c634"));

    // Invalid characters
    EXPECT_FALSE(is_valid_uuid("0191ec4g-9a6a-7d9a-9e58-69315570c634"));
    EXPECT_FALSE(is_valid_uuid("0191ec4d-9a6a-7d9a-9e58-69315570c63Z"));
}

TEST(MetadataValidatorTest, GenerateUuidV7) {
    std::string id1 = generate_uuid_v7();
    std::string id2 = generate_uuid_v7();
    EXPECT_TRUE(is_valid_uuid(id1));
    EXPECT_TRUE(is_valid_uuid(id2));
    EXPECT_NE(id1, id2);
}

TEST(MetadataValidatorTest, IsValidSha256Hex) {
    EXPECT_TRUE(is_valid_sha256_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    EXPECT_TRUE(is_valid_sha256_hex("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"));

    // Invalid length
    EXPECT_FALSE(is_valid_sha256_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"));
    EXPECT_FALSE(is_valid_sha256_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8555"));
    EXPECT_FALSE(is_valid_sha256_hex(""));

    // Invalid hex characters
    EXPECT_FALSE(is_valid_sha256_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85G"));
}

TEST(MetadataValidatorTest, CalculateExpectedChunkCount) {
    EXPECT_EQ(calculate_expected_chunk_count(0), 0);
    EXPECT_EQ(calculate_expected_chunk_count(1), 1);
    EXPECT_EQ(calculate_expected_chunk_count(k_standard_chunk_size - 1), 1);
    EXPECT_EQ(calculate_expected_chunk_count(k_standard_chunk_size), 1);
    EXPECT_EQ(calculate_expected_chunk_count(k_standard_chunk_size + 1), 2);
    EXPECT_EQ(calculate_expected_chunk_count(k_standard_chunk_size * 2), 2);
    EXPECT_EQ(calculate_expected_chunk_count(k_standard_chunk_size * 10), 10);
}

TEST(MetadataValidatorTest, UnpackClientCryptoMetadataJson) {
    std::string json_payload = R"({
        "encrypted_filename_hex": "48656c6c6f2e747874",
        "encrypted_mime_type_hex": "746578742f706c61696e",
        "metadata_nonce_hex": "0102030405060708090a0b0c0d0e0f101112131415161718",
        "metadata_tag_hex": "a1a2a3a4a5a6a7a8a9aaabacadaeafb0",
        "custom_key": "custom_val"
    })";

    CreateFileRequestDto dto;
    auto res = unpack_client_crypto_metadata(json_payload, dto);
    ASSERT_TRUE(res.is_valid) << res.error_message;
    EXPECT_EQ(dto.encrypted_filename.size(), 9); // "Hello.txt"
    ASSERT_TRUE(dto.encrypted_mime_type.has_value());
    EXPECT_EQ(dto.encrypted_mime_type->size(), 10); // "text/plain"
    EXPECT_EQ(dto.metadata_nonce.size(), 24);
    EXPECT_EQ(dto.metadata_tag.size(), 16);
    EXPECT_FALSE(dto.client_encryption_metadata_json.empty());
}

TEST(MetadataValidatorTest, UnpackClientCryptoMetadataBinaryPacked) {
    std::string raw;
    raw.append(24, '\x01'); // 24 bytes nonce
    raw.append(16, '\x02'); // 16 bytes tag
    raw.append("secret_ciphertext_filename");

    CreateFileRequestDto dto;
    auto res = unpack_client_crypto_metadata(raw, dto);
    ASSERT_TRUE(res.is_valid) << res.error_message;
    EXPECT_EQ(dto.metadata_nonce.size(), 24);
    EXPECT_EQ(dto.metadata_tag.size(), 16);
    EXPECT_EQ(dto.encrypted_filename.size(), 26);
}

TEST(MetadataValidatorTest, UnpackClientCryptoMetadataInvalid) {
    CreateFileRequestDto dto;
    EXPECT_FALSE(unpack_client_crypto_metadata("", dto).is_valid);
    EXPECT_FALSE(unpack_client_crypto_metadata("short", dto).is_valid);
}

TEST(MetadataValidatorTest, ValidateCreateFileRequestValid) {
    auto now = std::chrono::system_clock::now();
    CreateFileRequestDto dto{
        .file_id = "0191ec4d-9a6a-7d9a-9e58-69315570c634",
        .owner_user_id = "0191ec4d-9a6a-7d9a-9e58-69315570c635",
        .owner_device_id = "0191ec4d-9a6a-7d9a-9e58-69315570c636",
        .conversation_id = "0191ec4d-9a6a-7d9a-9e58-69315570c637",
        .encrypted_size_bytes = 10 * 1024 * 1024, // 10 MiB
        .expected_chunk_count = 3,                 // ceil(10 / 4) = 3
        .encryption_algorithm = "XChaCha20-Poly1305",
        .encrypted_filename = std::vector<uint8_t>(20, 0xAA),
        .metadata_nonce = std::vector<uint8_t>(24, 0xBB),
        .metadata_tag = std::vector<uint8_t>(16, 0xCC),
        .client_encryption_metadata_json = "{}",
        .retention_until = now + std::chrono::hours(24)
    };

    auto res = validate_create_file_request(dto, now);
    EXPECT_TRUE(res.is_valid) << res.error_message;
}

TEST(MetadataValidatorTest, ValidateCreateFileRequestRejections) {
    auto now = std::chrono::system_clock::now();
    CreateFileRequestDto base{
        .file_id = "0191ec4d-9a6a-7d9a-9e58-69315570c634",
        .owner_user_id = "0191ec4d-9a6a-7d9a-9e58-69315570c635",
        .owner_device_id = "0191ec4d-9a6a-7d9a-9e58-69315570c636",
        .encrypted_size_bytes = 4 * 1024 * 1024,
        .expected_chunk_count = 1,
        .encryption_algorithm = "XChaCha20-Poly1305",
        .encrypted_filename = {1, 2, 3},
        .metadata_nonce = std::vector<uint8_t>(24, 0),
        .metadata_tag = std::vector<uint8_t>(16, 0)
    };

    // Bad file UUID
    {
        auto dto = base;
        dto.file_id = "bad-uuid";
        EXPECT_FALSE(validate_create_file_request(dto, now).is_valid);
    }
    // Bad owner UUID
    {
        auto dto = base;
        dto.owner_user_id = "bad-uuid";
        EXPECT_FALSE(validate_create_file_request(dto, now).is_valid);
    }
    // Zero size
    {
        auto dto = base;
        dto.encrypted_size_bytes = 0;
        EXPECT_FALSE(validate_create_file_request(dto, now).is_valid);
    }
    // Oversized (> 5 GiB)
    {
        auto dto = base;
        dto.encrypted_size_bytes = 6ULL * 1024ULL * 1024ULL * 1024ULL;
        dto.expected_chunk_count = calculate_expected_chunk_count(dto.encrypted_size_bytes);
        EXPECT_FALSE(validate_create_file_request(dto, now).is_valid);
    }
    // Mismatched chunk count
    {
        auto dto = base;
        dto.expected_chunk_count = 99;
        EXPECT_FALSE(validate_create_file_request(dto, now).is_valid);
    }
    // Unsupported algorithm
    {
        auto dto = base;
        dto.encryption_algorithm = "AES-128-ECB";
        EXPECT_FALSE(validate_create_file_request(dto, now).is_valid);
    }
    // Empty filename
    {
        auto dto = base;
        dto.encrypted_filename.clear();
        EXPECT_FALSE(validate_create_file_request(dto, now).is_valid);
    }
    // Invalid nonce size
    {
        auto dto = base;
        dto.metadata_nonce = std::vector<uint8_t>(12, 0); // 12 instead of 24
        EXPECT_FALSE(validate_create_file_request(dto, now).is_valid);
    }
    // Invalid tag size
    {
        auto dto = base;
        dto.metadata_tag = std::vector<uint8_t>(32, 0); // 32 instead of 16
        EXPECT_FALSE(validate_create_file_request(dto, now).is_valid);
    }
    // Past expiration
    {
        auto dto = base;
        dto.retention_until = now - std::chrono::seconds(10);
        EXPECT_FALSE(validate_create_file_request(dto, now).is_valid);
    }
}

TEST(MetadataValidatorTest, ValidateCreateVersionRequest) {
    CreateFileVersionRequestDto valid_dto{
        .file_id = "0191ec4d-9a6a-7d9a-9e58-69315570c634",
        .version_number = 2,
        .encrypted_size_bytes = 1024,
        .minio_object_key = "objects/0191ec4d-9a6a-7d9a-9e58-69315570c634/2",
        .checksum_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    };

    EXPECT_TRUE(validate_create_version_request(valid_dto).is_valid);

    // Bad version number <= 0
    {
        auto dto = valid_dto;
        dto.version_number = 0;
        EXPECT_FALSE(validate_create_version_request(dto).is_valid);
    }
    // Path traversal in object key
    {
        auto dto = valid_dto;
        dto.minio_object_key = "objects/../../../etc/passwd";
        EXPECT_FALSE(validate_create_version_request(dto).is_valid);
    }
    // Leading slash in object key
    {
        auto dto = valid_dto;
        dto.minio_object_key = "/objects/file/1";
        EXPECT_FALSE(validate_create_version_request(dto).is_valid);
    }
    // Invalid checksum
    {
        auto dto = valid_dto;
        dto.checksum_sha256 = "not-a-valid-sha256";
        EXPECT_FALSE(validate_create_version_request(dto).is_valid);
    }
}

} // namespace
} // namespace securecloud::files
