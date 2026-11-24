#include "files/audit/files_audit_mapper.hpp"
#include "files/domain/files_outbox_entity.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace securecloud::files::audit {
namespace {

[[nodiscard]] std::string make_uuid_v7() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    const auto now_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());

    std::array<uint8_t, 16> bytes{};
    bytes[0] = static_cast<uint8_t>((now_ms >> 40) & 0xFFu);
    bytes[1] = static_cast<uint8_t>((now_ms >> 32) & 0xFFu);
    bytes[2] = static_cast<uint8_t>((now_ms >> 24) & 0xFFu);
    bytes[3] = static_cast<uint8_t>((now_ms >> 16) & 0xFFu);
    bytes[4] = static_cast<uint8_t>((now_ms >> 8) & 0xFFu);
    bytes[5] = static_cast<uint8_t>(now_ms & 0xFFu);

    const uint64_t r1 = rng();
    const uint64_t r2 = rng();
    bytes[6] = static_cast<uint8_t>(0x70u | ((r1 >> 56) & 0x0Fu)); // Version 7
    bytes[7] = static_cast<uint8_t>((r1 >> 48) & 0xFFu);
    bytes[8] = static_cast<uint8_t>(0x80u | ((r2 >> 56) & 0x3Fu)); // RFC 9562 variant 2
    bytes[9] = static_cast<uint8_t>((r2 >> 48) & 0xFFu);
    bytes[10] = static_cast<uint8_t>((r2 >> 40) & 0xFFu);
    bytes[11] = static_cast<uint8_t>((r2 >> 32) & 0xFFu);
    bytes[12] = static_cast<uint8_t>((r2 >> 24) & 0xFFu);
    bytes[13] = static_cast<uint8_t>((r2 >> 16) & 0xFFu);
    bytes[14] = static_cast<uint8_t>((r2 >> 8) & 0xFFu);
    bytes[15] = static_cast<uint8_t>(r2 & 0xFFu);

    char buf[37]{};
    std::snprintf(buf, sizeof(buf), "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", bytes[0],
                  bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10],
                  bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    return std::string(buf);
}

[[nodiscard]] FilesOutboxEntity make_valid_entity(std::string event_type,
                                                  std::optional<std::string> aggregate_id = std::nullopt) {
    FilesOutboxEntity entity;
    entity.event_id = make_uuid_v7();
    entity.aggregate_type = aggregate_id.has_value() ? "FILE" : "SERVICE";
    entity.aggregate_id = std::move(aggregate_id);
    entity.event_type = std::move(event_type);
    entity.severity = OutboxSeverity::Info;
    entity.created_at = std::chrono::system_clock::now();

    nlohmann::json payload;
    payload["owner_user_id"] = make_uuid_v7();
    payload["correlation_id"] = make_uuid_v7();
    payload["file_size"] = 1048576;
    payload["mime_type"] = "application/octet-stream";
    entity.payload_json = payload.dump();
    return entity;
}

} // namespace

TEST(FilesAuditMapperTest, MapsCanonicalE01ThroughE16EventsAndPassesAuditValidator) {
    const std::vector<std::string> canonical_events = {
        "file.created",             // E01
        "file.upload.completed",    // E02
        "file.upload.failed",       // E03
        "file.chunk.uploaded",      // E04
        "file.downloaded",          // E05
        "file.download.denied",     // E06
        "file.metadata.updated",    // E07
        "file.version.created",     // E08
        "file.version.restored",    // E09
        "file.access.granted",      // E10
        "file.access.revoked",      // E11
        "file.access.denied",       // E12
        "file.capability.issued",   // E13
        "file.capability.rejected", // E14
        "file.deleted",             // E15
        "file.purged",              // E16
    };

    const auto now = std::chrono::system_clock::now();
    for (const auto& ev_type : canonical_events) {
        const auto file_id = make_uuid_v7();
        auto entity = make_valid_entity(ev_type, file_id);
        entity.created_at = now;

        const auto mapped = FilesAuditMapper::to_validated_proto(entity, now, "files-node-1");
        EXPECT_TRUE(mapped.valid) << "Event '" << ev_type << "' failed validation: " << mapped.validation_error;
        EXPECT_EQ(mapped.proto.event_id(), entity.event_id);
        EXPECT_EQ(mapped.proto.event_type(), ev_type);
        EXPECT_EQ(mapped.proto.producer_service(), securecloud::audit::v1::PRODUCER_SERVICE_FILES);
        EXPECT_EQ(mapped.proto.producer_instance(), "files-node-1");
        EXPECT_EQ(mapped.proto.target_type(), securecloud::audit::v1::TARGET_TYPE_FILE);
        EXPECT_EQ(mapped.proto.target_id(), file_id);
        EXPECT_EQ(mapped.proto.actor_type(), securecloud::audit::v1::ACTOR_TYPE_USER);
    }
}

TEST(FilesAuditMapperTest, TranslatesLegacyFileEventsToCanonicalDotNotation) {
    const std::vector<std::pair<std::string, std::string>> legacy_cases = {
        {"FILE_CREATED", "file.created"},
        {"FILE_UPLOAD_INITIATED", "file.created"},
        {"FILE_UPLOAD_COMPLETED", "file.upload.completed"},
        {"FILE_FINALIZED", "file.upload.completed"},
        {"FILE_UPLOAD_FAILED", "file.upload.failed"},
        {"FILE_UPLOAD_ABORTED", "file.upload.failed"},
        {"FILE_CHUNK_UPLOADED", "file.chunk.uploaded"},
        {"FILE_DOWNLOADED", "file.downloaded"},
        {"FILE_DOWNLOAD_COMPLETED", "file.downloaded"},
        {"FILE_DOWNLOAD_DENIED", "file.download.denied"},
        {"FILE_METADATA_UPDATED", "file.metadata.updated"},
        {"FILE_RENAMED", "file.metadata.updated"},
        {"FILE_VERSION_CREATED", "file.version.created"},
        {"FILE_VERSION_RESTORED", "file.version.restored"},
        {"FILE_SHARED", "file.access.granted"},
        {"FILE_ACCESS_GRANTED", "file.access.granted"},
        {"FILE_UNSHARED", "file.access.revoked"},
        {"FILE_ACCESS_REVOKED", "file.access.revoked"},
        {"FILE_ACCESS_DENIED", "file.access.denied"},
        {"FILE_CAPABILITY_ISSUED", "file.capability.issued"},
        {"CAPABILITY_ISSUED", "file.capability.issued"},
        {"FILE_CAPABILITY_REJECTED", "file.capability.rejected"},
        {"CAPABILITY_REJECTED", "file.capability.rejected"},
        {"FILE_DELETED", "file.deleted"},
        {"FILE_SOFT_DELETED", "file.deleted"},
        {"FILE_PURGED", "file.purged"},
        {"FILE_HARD_DELETED", "file.purged"},
        {"FILE_CUSTOM_AUDIT_ACTION", "file.custom_audit_action"},
    };

    const auto now = std::chrono::system_clock::now();
    for (const auto& [legacy_name, expected_canonical] : legacy_cases) {
        auto entity = make_valid_entity(legacy_name, make_uuid_v7());
        entity.created_at = now;

        const auto mapped = FilesAuditMapper::to_validated_proto(entity, now);
        EXPECT_EQ(mapped.proto.event_type(), expected_canonical) << "Failed for legacy type: " << legacy_name;
        EXPECT_TRUE(mapped.valid) << "Legacy type '" << legacy_name
                                  << "' failed validation: " << mapped.validation_error;
    }
}

TEST(FilesAuditMapperTest, MapsNullAggregateIdToServiceTargetAndPromotesSecuritySeverity) {
    const auto now = std::chrono::system_clock::now();
    auto entity = make_valid_entity("CAPABILITY_REJECTED", std::nullopt);
    entity.created_at = now;
    entity.payload_json = R"({"actor_type":"SERVICE","actor_id":"gateway","causation_id":"cause-123"})";

    const auto mapped = FilesAuditMapper::to_validated_proto(entity, now);
    ASSERT_TRUE(mapped.valid) << mapped.validation_error;
    EXPECT_EQ(mapped.proto.event_type(), "file.capability.rejected");
    EXPECT_EQ(mapped.proto.target_type(), securecloud::audit::v1::TARGET_TYPE_SERVICE);
    EXPECT_EQ(mapped.proto.target_id(), "files");
    EXPECT_EQ(mapped.proto.actor_type(), securecloud::audit::v1::ACTOR_TYPE_SERVICE);
    EXPECT_EQ(mapped.proto.actor_id(), "gateway");
    EXPECT_EQ(mapped.proto.causation_id(), "cause-123");
    EXPECT_EQ(mapped.proto.correlation_id(), entity.event_id);
    EXPECT_EQ(mapped.proto.severity(), securecloud::audit::v1::SEVERITY_SECURITY);
}

TEST(FilesAuditMapperTest, Stage2ScrubberStripsAllForbiddenKeysCaseInsensitive) {
    const auto now = std::chrono::system_clock::now();
    auto entity = make_valid_entity("file.created", make_uuid_v7());
    entity.created_at = now;

    nlohmann::json payload;
    payload["owner_user_id"] = make_uuid_v7();
    payload["chunk_count"] = 4;
    payload["storage_tier"] = "hot";

    // Forbidden keys (various casings & suffixes)
    payload["password"] = "SECRET_VAL_01";
    payload["PASSWD"] = "SECRET_VAL_02";
    payload["secret"] = "SECRET_VAL_03";
    payload["token"] = "SECRET_VAL_04";
    payload["credential"] = "SECRET_VAL_05";
    payload["private_key"] = "SECRET_VAL_06";
    payload["privkey"] = "SECRET_VAL_07";
    payload["encryption_key"] = "SECRET_VAL_08";
    payload["key"] = "SECRET_VAL_09";
    payload["file_key"] = "SECRET_VAL_10";
    payload["master_key"] = "SECRET_VAL_11";
    payload["ciphertext"] = "SECRET_VAL_12";
    payload["encrypted_data"] = "SECRET_VAL_13";
    payload["plaintext"] = "SECRET_VAL_14";
    payload["encrypted_filename"] = "SECRET_VAL_15";
    payload["encrypted_mime_type"] = "SECRET_VAL_16";
    payload["metadata_nonce"] = "SECRET_VAL_17";
    payload["metadata_tag"] = "SECRET_VAL_18";
    payload["client_encryption_metadata"] = "SECRET_VAL_19";
    payload["capability_token"] = "SECRET_VAL_20";
    payload["s3_secret"] = "SECRET_VAL_21";
    payload["mfa"] = "SECRET_VAL_22";
    payload["totp"] = "SECRET_VAL_23";
    payload["seed"] = "SECRET_VAL_24";
    payload["salt"] = "SECRET_VAL_25";
    payload["filename"] = "SECRET_VAL_26";
    payload["file_name"] = "SECRET_VAL_27";
    entity.payload_json = payload.dump();

    const auto mapped = FilesAuditMapper::to_validated_proto(entity, now);
    ASSERT_TRUE(mapped.valid) << mapped.validation_error;

    const auto& meta = mapped.proto.metadata();
    EXPECT_EQ(meta.at("chunk_count"), "4");
    EXPECT_EQ(meta.at("storage_tier"), "hot");
    EXPECT_EQ(meta.size(), 2u);

    const std::string serialized = mapped.proto.SerializeAsString();
    EXPECT_EQ(serialized.find("SECRET_VAL_"), std::string::npos);
}

TEST(FilesAuditMapperTest, Stage2ScrubberHandlesNestedObjectsSafelyAndDropsDeepOrSecretFields) {
    const auto now = std::chrono::system_clock::now();
    auto entity = make_valid_entity("file.upload.completed", make_uuid_v7());
    entity.created_at = now;

    nlohmann::json payload;
    payload["owner_user_id"] = make_uuid_v7();
    payload["storage"] = {
        {"region", "eu-west-1"},
        {"part_count", 3},
        {"s3_secret", "LEAKED_NESTED_SECRET"},
        {"nested_obj", {{"deep_key", "deep_val"}}},
    };
    payload["crypto"] = {
        {"algorithm", "AES-256-GCM"},
        {"encryption_key", "LEAKED_CRYPTO_KEY"},
        {"metadata_nonce", "LEAKED_NONCE"},
    };
    payload["chunk_indices"] = nlohmann::json::array({0, 1, 2});
    entity.payload_json = payload.dump();

    const auto mapped = FilesAuditMapper::to_validated_proto(entity, now);
    ASSERT_TRUE(mapped.valid) << mapped.validation_error;

    const auto& meta = mapped.proto.metadata();
    EXPECT_EQ(meta.at("storage.region"), "eu-west-1");
    EXPECT_EQ(meta.at("storage.part_count"), "3");
    EXPECT_EQ(meta.at("crypto.algorithm"), "AES-256-GCM");
    EXPECT_EQ(meta.find("storage.s3_secret"), meta.end());
    EXPECT_EQ(meta.find("storage.nested_obj"), meta.end());
    EXPECT_EQ(meta.find("crypto.encryption_key"), meta.end());
    EXPECT_EQ(meta.find("crypto.metadata_nonce"), meta.end());
    EXPECT_EQ(meta.find("chunk_indices"), meta.end());

    const std::string serialized = mapped.proto.SerializeAsString();
    EXPECT_EQ(serialized.find("LEAKED_"), std::string::npos);
}

TEST(FilesAuditMapperTest, Stage2ScrubberRedactsBearerJwtPemAndPasswordHashValues) {
    const auto now = std::chrono::system_clock::now();
    auto entity = make_valid_entity("file.access.denied", make_uuid_v7());
    entity.created_at = now;

    const std::string fake_jwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3ItMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const std::string fake_pem =
        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw\n-----END PRIVATE KEY-----";
    const std::string fake_argon2 = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";
    const std::string fake_bcrypt = "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW";

    nlohmann::json payload;
    payload["owner_user_id"] = make_uuid_v7();
    payload["auth_header"] = "Bearer super-secret-access-token-xyz";
    payload["session_claim"] = fake_jwt;
    payload["material_blob"] = fake_pem;
    payload["verifier_a"] = fake_argon2;
    payload["verifier_b"] = fake_bcrypt;
    payload["safe_reason"] = "missing_read_permission";
    entity.payload_json = payload.dump();

    const auto mapped = FilesAuditMapper::to_validated_proto(entity, now);
    ASSERT_TRUE(mapped.valid) << mapped.validation_error;

    const auto& meta = mapped.proto.metadata();
    EXPECT_EQ(meta.at("auth_header"), "[REDACTED]");
    EXPECT_EQ(meta.at("session_claim"), "[REDACTED]");
    EXPECT_EQ(meta.at("material_blob"), "[REDACTED]");
    EXPECT_EQ(meta.at("verifier_a"), "[REDACTED]");
    EXPECT_EQ(meta.at("verifier_b"), "[REDACTED]");
    EXPECT_EQ(meta.at("safe_reason"), "missing_read_permission");

    const std::string serialized = mapped.proto.SerializeAsString();
    EXPECT_EQ(serialized.find("super-secret-access-token-xyz"), std::string::npos);
    EXPECT_EQ(serialized.find("eyJhbGci"), std::string::npos);
    EXPECT_EQ(serialized.find("BEGIN PRIVATE KEY"), std::string::npos);
    EXPECT_EQ(serialized.find("$argon2id$"), std::string::npos);
    EXPECT_EQ(serialized.find("$2b$12$"), std::string::npos);
}

TEST(FilesAuditMapperTest, EnforcesMetadataEntryCountKeyFormatAndValueLengthBounds) {
    const auto now = std::chrono::system_clock::now();
    auto entity = make_valid_entity("file.metadata.updated", make_uuid_v7());
    entity.created_at = now;

    nlohmann::json payload;
    payload["owner_user_id"] = make_uuid_v7();
    payload["invalid key with spaces"] = "dropped";
    payload["invalid$key"] = "dropped";
    payload[std::string(65, 'k')] = "oversized_key_dropped";
    payload["long_value"] = std::string(1500, 'v');

    for (int i = 0; i < 65; ++i) {
        payload["metric_" + std::to_string(i)] = i;
    }
    entity.payload_json = payload.dump();

    const auto mapped = FilesAuditMapper::to_validated_proto(entity, now);
    ASSERT_TRUE(mapped.valid) << mapped.validation_error;

    const auto& meta = mapped.proto.metadata();
    EXPECT_LE(meta.size(), FilesAuditMapper::k_max_metadata_entries);
    EXPECT_EQ(meta.find("invalid key with spaces"), meta.end());
    EXPECT_EQ(meta.find("invalid$key"), meta.end());
    EXPECT_EQ(meta.find(std::string(65, 'k')), meta.end());
    ASSERT_TRUE(meta.contains("long_value"));
    EXPECT_EQ(meta.at("long_value").size(), FilesAuditMapper::k_max_metadata_value_length);
}

TEST(FilesAuditMapperTest, HandlesMalformedPayloadGracefullyAndRejectsNonUuidV7PreFlight) {
    const auto now = std::chrono::system_clock::now();

    // Valid UUIDv7 with malformed JSON still translates safely with system fallback
    FilesOutboxEntity valid_id_bad_json;
    valid_id_bad_json.event_id = make_uuid_v7();
    valid_id_bad_json.aggregate_id = make_uuid_v7();
    valid_id_bad_json.event_type = "FILE_DELETED";
    valid_id_bad_json.created_at = now;
    valid_id_bad_json.payload_json = "{bad_json: invalid";

    const auto mapped_valid = FilesAuditMapper::to_validated_proto(valid_id_bad_json, now);
    EXPECT_TRUE(mapped_valid.valid) << mapped_valid.validation_error;
    EXPECT_EQ(mapped_valid.proto.event_type(), "file.deleted");
    EXPECT_EQ(mapped_valid.proto.correlation_id(), valid_id_bad_json.event_id);
    EXPECT_EQ(mapped_valid.proto.actor_id(), "system");
    EXPECT_EQ(mapped_valid.proto.actor_type(), securecloud::audit::v1::ACTOR_TYPE_SYSTEM);

    // Corrupted non-UUIDv7 event_id must fail pre-flight validation locally
    FilesOutboxEntity invalid_id_entity;
    invalid_id_entity.event_id = "not-a-valid-uuidv7";
    invalid_id_entity.aggregate_id = make_uuid_v7();
    invalid_id_entity.event_type = "FILE_CREATED";
    invalid_id_entity.created_at = now;
    invalid_id_entity.payload_json = R"({"secret":"MUST_NOT_LEAK_IN_ERRORS"})";

    const auto mapped_invalid = FilesAuditMapper::to_validated_proto(invalid_id_entity, now);
    EXPECT_FALSE(mapped_invalid.valid);
    EXPECT_FALSE(mapped_invalid.validation_error.empty());
    EXPECT_EQ(mapped_invalid.validation_error.find("MUST_NOT_LEAK_IN_ERRORS"), std::string::npos);
    EXPECT_EQ(mapped_invalid.proto.SerializeAsString().find("MUST_NOT_LEAK_IN_ERRORS"), std::string::npos);
}

} // namespace securecloud::files::audit
