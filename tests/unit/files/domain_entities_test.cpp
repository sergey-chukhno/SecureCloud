#include "files/db/pqxx_mappers.hpp"
#include "files/domain/encrypted_file_metadata_entity.hpp"
#include "files/domain/file_access_entity.hpp"
#include "files/domain/file_chunk_entity.hpp"
#include "files/domain/file_entity.hpp"
#include "files/domain/file_transfer_entity.hpp"
#include "files/domain/file_version_entity.hpp"
#include "files/domain/files_outbox_entity.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace securecloud::files::db {
namespace {

// --- 1. Enum String Conversion Tests ---

TEST(DomainEntitiesTest, FileStatusEnumRoundtrip) {
    const std::vector<std::pair<FileStatus, std::string>> cases = {
        {FileStatus::Created, "CREATED"},       {FileStatus::Uploading, "UPLOADING"},
        {FileStatus::Finalizing, "FINALIZING"}, {FileStatus::Available, "AVAILABLE"},
        {FileStatus::Expired, "EXPIRED"},       {FileStatus::Deleted, "DELETED"},
        {FileStatus::Failed, "FAILED"}};

    for (const auto& [status, str] : cases) {
        EXPECT_EQ(to_string(status), str);
        EXPECT_EQ(file_status_from_string(str), status);
    }

    EXPECT_THROW(file_status_from_string("INVALID"), InvalidEnumException);
    EXPECT_THROW(file_status_from_string(""), InvalidEnumException);
    EXPECT_THROW(file_status_from_string("created"), InvalidEnumException);
}

TEST(DomainEntitiesTest, TransferTypeEnumRoundtrip) {
    EXPECT_EQ(to_string(TransferType::Upload), "UPLOAD");
    EXPECT_EQ(to_string(TransferType::Download), "DOWNLOAD");

    EXPECT_EQ(transfer_type_from_string("UPLOAD"), TransferType::Upload);
    EXPECT_EQ(transfer_type_from_string("DOWNLOAD"), TransferType::Download);

    EXPECT_THROW(transfer_type_from_string("UNKNOWN"), InvalidEnumException);
    EXPECT_THROW(transfer_type_from_string(""), InvalidEnumException);
}

TEST(DomainEntitiesTest, TransferStatusEnumRoundtrip) {
    const std::vector<std::pair<TransferStatus, std::string>> cases = {
        {TransferStatus::Created, "CREATED"},       {TransferStatus::Transferring, "TRANSFERRING"},
        {TransferStatus::Finalizing, "FINALIZING"}, {TransferStatus::Completed, "COMPLETED"},
        {TransferStatus::Failed, "FAILED"},         {TransferStatus::Expired, "EXPIRED"},
        {TransferStatus::Cancelled, "CANCELLED"}};

    for (const auto& [status, str] : cases) {
        EXPECT_EQ(to_string(status), str);
        EXPECT_EQ(transfer_status_from_string(str), status);
    }

    EXPECT_THROW(transfer_status_from_string("PROCESSING"), InvalidEnumException);
}

TEST(DomainEntitiesTest, ChunkStatusEnumRoundtrip) {
    EXPECT_EQ(to_string(ChunkStatus::Received), "RECEIVED");
    EXPECT_EQ(to_string(ChunkStatus::Committed), "COMMITTED");

    EXPECT_EQ(chunk_status_from_string("RECEIVED"), ChunkStatus::Received);
    EXPECT_EQ(chunk_status_from_string("COMMITTED"), ChunkStatus::Committed);

    EXPECT_THROW(chunk_status_from_string("PENDING"), InvalidEnumException);
}

TEST(DomainEntitiesTest, FilePermissionEnumRoundtrip) {
    EXPECT_EQ(to_string(FilePermission::Read), "READ");
    EXPECT_EQ(to_string(FilePermission::Write), "WRITE");
    EXPECT_EQ(to_string(FilePermission::Admin), "ADMIN");

    EXPECT_EQ(file_permission_from_string("READ"), FilePermission::Read);
    EXPECT_EQ(file_permission_from_string("WRITE"), FilePermission::Write);
    EXPECT_EQ(file_permission_from_string("ADMIN"), FilePermission::Admin);

    EXPECT_THROW(file_permission_from_string("EXECUTE"), InvalidEnumException);
}

TEST(DomainEntitiesTest, OutboxStatusEnumRoundtrip) {
    EXPECT_EQ(to_string(OutboxStatus::Pending), "PENDING");
    EXPECT_EQ(to_string(OutboxStatus::Published), "PUBLISHED");
    EXPECT_EQ(to_string(OutboxStatus::Failed), "FAILED");

    EXPECT_EQ(outbox_status_from_string("PENDING"), OutboxStatus::Pending);
    EXPECT_EQ(outbox_status_from_string("PUBLISHED"), OutboxStatus::Published);
    EXPECT_EQ(outbox_status_from_string("FAILED"), OutboxStatus::Failed);

    EXPECT_THROW(outbox_status_from_string("IN_PROGRESS"), InvalidEnumException);
}

// --- 2. Timestamp ISO 8601 Tests ---

TEST(DomainEntitiesTest, TimestampRoundtripUtc) {
    std::string iso_input = "2026-09-25T10:30:45.123456Z";
    auto tp = from_iso8601(iso_input);
    std::string iso_output = to_iso8601(tp);
    EXPECT_EQ(iso_output, iso_input);
}

TEST(DomainEntitiesTest, TimestampParsesWithoutFractionalSeconds) {
    std::string iso_input = "2026-09-25T10:30:45Z";
    auto tp = from_iso8601(iso_input);
    std::string iso_output = to_iso8601(tp);
    EXPECT_EQ(iso_output, "2026-09-25T10:30:45Z");
}

TEST(DomainEntitiesTest, TimestampParsesSpaceSeparatorAndPostgresFormat) {
    std::string pg_input = "2026-09-25 10:30:45+00";
    auto tp = from_iso8601(pg_input);
    std::string iso_output = to_iso8601(tp);
    EXPECT_EQ(iso_output, "2026-09-25T10:30:45Z");
}

TEST(DomainEntitiesTest, TimestampParsesTimezoneOffsetsAccurately) {
    // 12:30:45+02:00 is 10:30:45 UTC
    std::string offset_input = "2026-09-25T12:30:45+02:00";
    auto tp = from_iso8601(offset_input);
    std::string iso_output = to_iso8601(tp);
    EXPECT_EQ(iso_output, "2026-09-25T10:30:45Z");

    // 05:30:45-05:00 is 10:30:45 UTC
    std::string negative_offset = "2026-09-25T05:30:45-05:00";
    auto tp2 = from_iso8601(negative_offset);
    EXPECT_EQ(to_iso8601(tp2), "2026-09-25T10:30:45Z");
}

TEST(DomainEntitiesTest, TimestampRejectsMalformedStrings) {
    EXPECT_THROW(from_iso8601(""), TimestampParseException);
    EXPECT_THROW(from_iso8601("invalid-date"), TimestampParseException);
    EXPECT_THROW(from_iso8601("2026/09/25T10:30:45Z"), TimestampParseException);
    EXPECT_THROW(from_iso8601("2026-13-25T10:30:45Z"), TimestampParseException);  // month 13
    EXPECT_THROW(from_iso8601("2026-09-32T10:30:45Z"), TimestampParseException);  // day 32
    EXPECT_THROW(from_iso8601("2026-09-25T25:30:45Z"), TimestampParseException);  // hour 25
    EXPECT_THROW(from_iso8601("2026-09-25T10:65:45Z"), TimestampParseException);  // min 65
    EXPECT_THROW(from_iso8601("2026-09-25T10:30:45.Z"), TimestampParseException); // missing frac digits
}

// --- 3. PostgreSQL Bytea Tests ---

TEST(DomainEntitiesTest, ByteaHexRoundtrip) {
    std::vector<uint8_t> raw_bytes = {0x00, 0x01, 0x02, 0x7F, 0x80, 0xFE, 0xFF, 0x4A, 0x6B};
    std::string hex_str = to_bytea_hex(raw_bytes);
    EXPECT_EQ(hex_str, "\\x0001027f80feff4a6b");

    auto decoded = from_bytea_hex(hex_str);
    EXPECT_EQ(decoded, raw_bytes);
}

TEST(DomainEntitiesTest, ByteaDecodesWithOrWithoutPrefix) {
    std::vector<uint8_t> expected = {0xDE, 0xAD, 0xBE, 0xEF};

    EXPECT_EQ(from_bytea_hex("\\xdeadbeef"), expected);
    EXPECT_EQ(from_bytea_hex("\\\\xdeadbeef"), expected);
    EXPECT_EQ(from_bytea_hex("DEADBEEF"), expected);
    EXPECT_TRUE(from_bytea_hex("").empty());
}

TEST(DomainEntitiesTest, ByteaRejectsMalformedHex) {
    // Odd number of hex characters
    EXPECT_THROW(from_bytea_hex("\\xdeadbee"), ByteaParseException);
    // Invalid non-hex characters
    EXPECT_THROW(from_bytea_hex("\\xdeadzzef"), ByteaParseException);
}

// --- 4. FileEntity Row Mapping Tests ---

TEST(DomainEntitiesTest, MapFileEntityCompleteRow) {
    RowBuilder builder;
    builder.set("file_id", "550e8400-e29b-41d4-a716-446655440000")
        .set("owner_user_id", "660e8400-e29b-41d4-a716-446655440001")
        .set("owner_device_id", "770e8400-e29b-41d4-a716-446655440002")
        .set("conversation_id", "880e8400-e29b-41d4-a716-446655440003")
        .set("encrypted_size", "10485760")
        .set("content_type", "application/pdf")
        .set("encryption_algorithm", "XChaCha20-Poly1305")
        .set("status", "AVAILABLE")
        .set("retention_until", "2027-01-01T00:00:00Z")
        .set("created_at", "2026-09-25T10:00:00Z")
        .set("updated_at", "2026-09-25T10:05:00Z");

    pqxx::row row = builder.build();
    FileEntity entity = file_from_row(row);

    EXPECT_EQ(entity.file_id, "550e8400-e29b-41d4-a716-446655440000");
    EXPECT_EQ(entity.owner_user_id, "660e8400-e29b-41d4-a716-446655440001");
    EXPECT_EQ(entity.owner_device_id, "770e8400-e29b-41d4-a716-446655440002");
    ASSERT_TRUE(entity.conversation_id.has_value());
    EXPECT_EQ(*entity.conversation_id, "880e8400-e29b-41d4-a716-446655440003");
    EXPECT_EQ(entity.encrypted_size, 10485760);
    ASSERT_TRUE(entity.content_type.has_value());
    EXPECT_EQ(*entity.content_type, "application/pdf");
    EXPECT_EQ(entity.encryption_algorithm, "XChaCha20-Poly1305");
    EXPECT_EQ(entity.status, FileStatus::Available);
    ASSERT_TRUE(entity.retention_until.has_value());
    EXPECT_EQ(to_iso8601(*entity.retention_until), "2027-01-01T00:00:00Z");
    EXPECT_EQ(to_iso8601(entity.created_at), "2026-09-25T10:00:00Z");
    EXPECT_EQ(to_iso8601(entity.updated_at), "2026-09-25T10:05:00Z");
}

TEST(DomainEntitiesTest, MapFileEntityNullableFieldsNull) {
    RowBuilder builder;
    builder.set("file_id", "550e8400-e29b-41d4-a716-446655440000")
        .set("owner_user_id", "660e8400-e29b-41d4-a716-446655440001")
        .set("owner_device_id", "770e8400-e29b-41d4-a716-446655440002")
        .set_null("conversation_id")
        .set("encrypted_size", "2048")
        .set_null("content_type")
        .set("encryption_algorithm", "XChaCha20-Poly1305")
        .set("status", "CREATED")
        .set_null("retention_until")
        .set("created_at", "2026-09-25T10:00:00Z")
        .set("updated_at", "2026-09-25T10:00:00Z");

    pqxx::row row = builder.build();
    FileEntity entity = file_from_row(row);

    EXPECT_FALSE(entity.conversation_id.has_value());
    EXPECT_FALSE(entity.content_type.has_value());
    EXPECT_FALSE(entity.retention_until.has_value());
    EXPECT_EQ(entity.status, FileStatus::Created);
    EXPECT_EQ(entity.encrypted_size, 2048);
}

// --- 5. FileVersionEntity Row Mapping Tests ---

TEST(DomainEntitiesTest, MapFileVersionEntityRow) {
    RowBuilder builder;
    builder.set("version_id", "110e8400-e29b-41d4-a716-446655440000")
        .set("file_id", "550e8400-e29b-41d4-a716-446655440000")
        .set("version_number", "2")
        .set("encrypted_size", "4096")
        .set("minio_object_key", "files/550e8400/v2.bin")
        .set("checksum_sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        .set("created_at", "2026-09-25T10:15:00Z")
        .set("is_active", "t");

    pqxx::row row = builder.build();
    FileVersionEntity version = file_version_from_row(row);

    EXPECT_EQ(version.version_id, "110e8400-e29b-41d4-a716-446655440000");
    EXPECT_EQ(version.file_id, "550e8400-e29b-41d4-a716-446655440000");
    EXPECT_EQ(version.version_number, 2);
    EXPECT_EQ(version.encrypted_size, 4096);
    EXPECT_EQ(version.minio_object_key, "files/550e8400/v2.bin");
    EXPECT_EQ(version.checksum_sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_EQ(to_iso8601(version.created_at), "2026-09-25T10:15:00Z");
    EXPECT_TRUE(version.is_active);
}

// --- 6. EncryptedFileMetadataEntity Row Mapping Tests ---

TEST(DomainEntitiesTest, MapEncryptedFileMetadataEntityRow) {
    RowBuilder builder;
    builder.set("file_id", "550e8400-e29b-41d4-a716-446655440000")
        .set("encrypted_filename", "\\xabcdef0123456789")
        .set("encrypted_mime_type", "\\x12345678")
        .set("metadata_nonce", "\\x99887766554433221100")
        .set("metadata_tag", "\\x0102030405060708090a0b0c0d0e0f10")
        .set("client_encryption_metadata", "{\"kdf\":\"Argon2id\",\"salt\":\"somesalt\"}")
        .set("updated_at", "2026-09-25T10:20:00Z");

    pqxx::row row = builder.build();
    EncryptedFileMetadataEntity meta = encrypted_metadata_from_row(row);

    EXPECT_EQ(meta.file_id, "550e8400-e29b-41d4-a716-446655440000");
    EXPECT_EQ(to_bytea_hex(meta.encrypted_filename), "\\xabcdef0123456789");
    ASSERT_TRUE(meta.encrypted_mime_type.has_value());
    EXPECT_EQ(to_bytea_hex(*meta.encrypted_mime_type), "\\x12345678");
    EXPECT_EQ(to_bytea_hex(meta.metadata_nonce), "\\x99887766554433221100");
    EXPECT_EQ(meta.metadata_tag.size(), 16);
    EXPECT_EQ(meta.client_encryption_metadata_json, "{\"kdf\":\"Argon2id\",\"salt\":\"somesalt\"}");
    EXPECT_EQ(to_iso8601(meta.updated_at), "2026-09-25T10:20:00Z");
}

TEST(DomainEntitiesTest, MapEncryptedFileMetadataNullMimeType) {
    RowBuilder builder;
    builder.set("file_id", "550e8400-e29b-41d4-a716-446655440000")
        .set("encrypted_filename", "\\xabcdef01")
        .set_null("encrypted_mime_type")
        .set("metadata_nonce", "\\x11223344")
        .set("metadata_tag", "\\x55667788")
        .set("client_encryption_metadata", "{}")
        .set("updated_at", "2026-09-25T10:20:00Z");

    pqxx::row row = builder.build();
    EncryptedFileMetadataEntity meta = encrypted_metadata_from_row(row);

    EXPECT_FALSE(meta.encrypted_mime_type.has_value());
}

// --- 7. FileTransferEntity Row Mapping Tests ---

TEST(DomainEntitiesTest, MapFileTransferEntityRow) {
    RowBuilder builder;
    builder.set("transfer_id", "220e8400-e29b-41d4-a716-446655440000")
        .set("file_id", "550e8400-e29b-41d4-a716-446655440000")
        .set("transfer_type", "UPLOAD")
        .set("initiator_user_id", "660e8400-e29b-41d4-a716-446655440001")
        .set("initiator_device_id", "770e8400-e29b-41d4-a716-446655440002")
        .set("status", "TRANSFERRING")
        .set("total_chunks", "10")
        .set("accepted_chunks", "3")
        .set("total_bytes", "10485760")
        .set("transferred_bytes", "3145728")
        .set("created_at", "2026-09-25T10:00:00Z")
        .set("updated_at", "2026-09-25T10:05:00Z")
        .set("expires_at", "2026-09-25T11:00:00Z");

    pqxx::row row = builder.build();
    FileTransferEntity transfer = file_transfer_from_row(row);

    EXPECT_EQ(transfer.transfer_id, "220e8400-e29b-41d4-a716-446655440000");
    EXPECT_EQ(transfer.file_id, "550e8400-e29b-41d4-a716-446655440000");
    EXPECT_EQ(transfer.transfer_type, TransferType::Upload);
    EXPECT_EQ(transfer.status, TransferStatus::Transferring);
    EXPECT_EQ(transfer.total_chunks, 10);
    EXPECT_EQ(transfer.accepted_chunks, 3);
    EXPECT_EQ(transfer.total_bytes, 10485760);
    EXPECT_EQ(transfer.transferred_bytes, 3145728);
    EXPECT_EQ(to_iso8601(transfer.expires_at), "2026-09-25T11:00:00Z");
}

// --- 8. FileChunkEntity Row Mapping Tests ---

TEST(DomainEntitiesTest, MapFileChunkEntityRow) {
    RowBuilder builder;
    builder.set("chunk_id", "330e8400-e29b-41d4-a716-446655440000")
        .set("transfer_id", "220e8400-e29b-41d4-a716-446655440000")
        .set("chunk_index", "0")
        .set("byte_offset", "0")
        .set("chunk_size", "1048576")
        .set("chunk_hash_sha256", "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
        .set("minio_chunk_key", "chunks/220e8400/part_0.bin")
        .set("status", "RECEIVED")
        .set("created_at", "2026-09-25T10:02:00Z");

    pqxx::row row = builder.build();
    FileChunkEntity chunk = file_chunk_from_row(row);

    EXPECT_EQ(chunk.chunk_id, "330e8400-e29b-41d4-a716-446655440000");
    EXPECT_EQ(chunk.transfer_id, "220e8400-e29b-41d4-a716-446655440000");
    EXPECT_EQ(chunk.chunk_index, 0);
    EXPECT_EQ(chunk.byte_offset, 0);
    EXPECT_EQ(chunk.chunk_size, 1048576);
    EXPECT_EQ(chunk.chunk_hash_sha256, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    EXPECT_EQ(chunk.minio_chunk_key, "chunks/220e8400/part_0.bin");
    EXPECT_EQ(chunk.status, ChunkStatus::Received);
    EXPECT_EQ(to_iso8601(chunk.created_at), "2026-09-25T10:02:00Z");
}

// --- 9. FileAccessEntity Row Mapping Tests ---

TEST(DomainEntitiesTest, MapFileAccessEntityRow) {
    RowBuilder builder;
    builder.set("access_id", "440e8400-e29b-41d4-a716-446655440000")
        .set("file_id", "550e8400-e29b-41d4-a716-446655440000")
        .set("grantee_user_id", "990e8400-e29b-41d4-a716-446655440000")
        .set("grantee_device_id", "aa0e8400-e29b-41d4-a716-446655440000")
        .set("permission", "WRITE")
        .set("granted_by", "660e8400-e29b-41d4-a716-446655440001")
        .set("granted_at", "2026-09-25T10:01:00Z")
        .set("revoked_at", "2026-09-25T12:00:00Z");

    pqxx::row row = builder.build();
    FileAccessEntity access = file_access_from_row(row);

    EXPECT_EQ(access.access_id, "440e8400-e29b-41d4-a716-446655440000");
    EXPECT_EQ(access.file_id, "550e8400-e29b-41d4-a716-446655440000");
    EXPECT_EQ(access.grantee_user_id, "990e8400-e29b-41d4-a716-446655440000");
    ASSERT_TRUE(access.grantee_device_id.has_value());
    EXPECT_EQ(*access.grantee_device_id, "aa0e8400-e29b-41d4-a716-446655440000");
    EXPECT_EQ(access.permission, FilePermission::Write);
    EXPECT_EQ(access.granted_by, "660e8400-e29b-41d4-a716-446655440001");
    EXPECT_EQ(to_iso8601(access.granted_at), "2026-09-25T10:01:00Z");
    ASSERT_TRUE(access.revoked_at.has_value());
    EXPECT_EQ(to_iso8601(*access.revoked_at), "2026-09-25T12:00:00Z");
}

TEST(DomainEntitiesTest, MapFileAccessEntityNullableNull) {
    RowBuilder builder;
    builder.set("access_id", "440e8400-e29b-41d4-a716-446655440000")
        .set("file_id", "550e8400-e29b-41d4-a716-446655440000")
        .set("grantee_user_id", "990e8400-e29b-41d4-a716-446655440000")
        .set_null("grantee_device_id")
        .set("permission", "READ")
        .set("granted_by", "660e8400-e29b-41d4-a716-446655440001")
        .set("granted_at", "2026-09-25T10:01:00Z")
        .set_null("revoked_at");

    pqxx::row row = builder.build();
    FileAccessEntity access = file_access_from_row(row);

    EXPECT_FALSE(access.grantee_device_id.has_value());
    EXPECT_FALSE(access.revoked_at.has_value());
    EXPECT_EQ(access.permission, FilePermission::Read);
}

// --- 10. FilesOutboxEntity Row Mapping Tests ---

TEST(DomainEntitiesTest, MapFilesOutboxEntityRow) {
    RowBuilder builder;
    builder.set("event_id", "880e8400-e29b-41d4-a716-446655440000")
        .set("aggregate_type", "FILE")
        .set("aggregate_id", "550e8400-e29b-41d4-a716-446655440000")
        .set("event_type", "FILE_UPLOAD_COMPLETED")
        .set("payload_json", "{\"file_id\":\"550e8400\",\"size\":10485760}")
        .set("status", "PENDING")
        .set("retry_count", "0")
        .set("created_at", "2026-09-25T10:05:00Z")
        .set_null("processed_at");

    pqxx::row row = builder.build();
    FilesOutboxEntity outbox = files_outbox_from_row(row);

    EXPECT_EQ(outbox.event_id, "880e8400-e29b-41d4-a716-446655440000");
    EXPECT_EQ(outbox.aggregate_type, "FILE");
    EXPECT_EQ(outbox.aggregate_id, "550e8400-e29b-41d4-a716-446655440000");
    EXPECT_EQ(outbox.event_type, "FILE_UPLOAD_COMPLETED");
    EXPECT_EQ(outbox.payload_json, "{\"file_id\":\"550e8400\",\"size\":10485760}");
    EXPECT_EQ(outbox.status, OutboxStatus::Pending);
    EXPECT_EQ(outbox.retry_count, 0);
    EXPECT_EQ(to_iso8601(outbox.created_at), "2026-09-25T10:05:00Z");
    EXPECT_FALSE(outbox.processed_at.has_value());
}

TEST(DomainEntitiesTest, MapFilesOutboxEntityProcessed) {
    RowBuilder builder;
    builder.set("event_id", "880e8400-e29b-41d4-a716-446655440000")
        .set("aggregate_type", "FILE")
        .set("aggregate_id", "550e8400-e29b-41d4-a716-446655440000")
        .set("event_type", "FILE_UPLOAD_COMPLETED")
        .set("payload_json", "{}")
        .set("status", "PUBLISHED")
        .set("retry_count", "1")
        .set("created_at", "2026-09-25T10:05:00Z")
        .set("processed_at", "2026-09-25T10:06:00Z");

    pqxx::row row = builder.build();
    FilesOutboxEntity outbox = files_outbox_from_row(row);

    EXPECT_EQ(outbox.status, OutboxStatus::Published);
    EXPECT_EQ(outbox.retry_count, 1);
    ASSERT_TRUE(outbox.processed_at.has_value());
    EXPECT_EQ(to_iso8601(*outbox.processed_at), "2026-09-25T10:06:00Z");
}

} // namespace
} // namespace securecloud::files::db
