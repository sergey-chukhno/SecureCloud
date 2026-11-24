#include "auth/domain/audit_event.hpp"
#include "files/audit/files_audit_mapper.hpp"
#include "files/audit/files_audit_proto_validator.hpp"
#include "files/domain/files_outbox_entity.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <random>

namespace securecloud::files::audit {
namespace {
std::string uuid_v7() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    const auto ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    std::array<uint8_t, 16> b{};
    for (size_t i = 0; i < 6; ++i)
        b[5 - i] = static_cast<uint8_t>(ms >> (i * 8));
    const auto r1 = rng(), r2 = rng();
    b[6] = static_cast<uint8_t>(0x70u | ((r1 >> 56) & 0x0fu));
    b[7] = static_cast<uint8_t>(r1 >> 48);
    b[8] = static_cast<uint8_t>(0x80u | ((r2 >> 56) & 0x3fu));
    for (size_t i = 9; i < b.size(); ++i)
        b[i] = static_cast<uint8_t>(r2 >> ((15 - i) * 8));
    char out[37]{};
    std::snprintf(out, sizeof(out), "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", b[0], b[1],
                  b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    return out;
}

FilesOutboxEntity entity(std::string event_type) {
    FilesOutboxEntity e;
    e.event_id = uuid_v7();
    e.aggregate_type = "FILE";
    e.aggregate_id = uuid_v7();
    e.event_type = std::move(event_type);
    e.created_at = std::chrono::system_clock::now();
    nlohmann::json payload;
    payload["owner_user_id"] = uuid_v7();
    payload["correlation_id"] = uuid_v7();
    payload["file_size"] = 1024;
    payload["chunk_count"] = 2;
    e.payload_json = payload.dump();
    return e;
}
} // namespace

TEST(FilesOutboxAuditTest, CanonicalCatalogEventsPassTheRealAuditValidator) {
    const std::array<std::string_view, 16> types = {"file.created",
                                                    "file.version.created",
                                                    "file.upload.initiated",
                                                    "file.upload.completed",
                                                    "file.upload.cancelled",
                                                    "file.upload.expired",
                                                    "file.chunk.integrity_failed",
                                                    "file.finalization.failed",
                                                    "file.download.initiated",
                                                    "file.access.granted",
                                                    "file.access.revoked",
                                                    "file.access.denied",
                                                    "file.capability.issued",
                                                    "file.capability.rejected",
                                                    "file.deleted",
                                                    "file.expired"};
    FilesAuditProtoValidator validator;
    const auto now = std::chrono::system_clock::now();
    for (const auto type : types) {
        auto mapped = FilesAuditMapper::to_validated_proto(entity(std::string(type)), now, "files-test");
        ASSERT_TRUE(mapped.valid) << type << ": " << mapped.validation_error;
        const auto real_validation = validator.validate(mapped.proto, now);
        EXPECT_TRUE(real_validation.valid) << type << ": " << real_validation.joined_errors();
        EXPECT_EQ(mapped.proto.event_type(), type);
        EXPECT_EQ(mapped.proto.producer_service(), securecloud::audit::v1::PRODUCER_SERVICE_FILES);
    }
}

TEST(FilesOutboxAuditTest, LegacyLifecycleNamesNormalizeAndPassValidator) {
    const std::array<std::pair<std::string_view, std::string_view>, 8> cases = {
        {{"FILE_CREATED", "file.created"},
         {"FILE_VERSION_CREATED", "file.version.created"},
         {"FILE_UPLOADING", "file.upload.initiated"},
         {"FILE_AVAILABLE", "file.upload.completed"},
         {"TRANSFER_CANCELLED", "file.upload.cancelled"},
         {"FILE_FAILED", "file.finalization.failed"},
         {"FILE_ACCESS_REVOKED", "file.access.revoked"},
         {"FILE_EXPIRED", "file.expired"}}};
    FilesAuditProtoValidator validator;
    for (const auto& [legacy, canonical] : cases) {
        const auto now = std::chrono::system_clock::now();
        auto mapped = FilesAuditMapper::to_validated_proto(entity(std::string(legacy)), now);
        ASSERT_TRUE(mapped.valid) << legacy << ": " << mapped.validation_error;
        EXPECT_EQ(mapped.proto.event_type(), canonical);
        EXPECT_TRUE(validator.validate(mapped.proto, now).valid) << legacy;
    }
}

TEST(FilesOutboxAuditTest, TwoStageScrubbingRemovesNestedSecretsAndFilenameMaterial) {
    auto e = entity("file.created");
    auto payload = nlohmann::json::parse(e.payload_json);
    payload["encrypted_filename"] = "secret-report.pdf";
    payload["client_encryption_metadata"] = {{"metadata_nonce", "nonce-secret"}, {"metadata_tag", "tag-secret"}};
    payload["nested"] = {{"encryption_key", "key-secret"},
                         {"s3_secret_key", "s3-secret"},
                         {"authorization", "Bearer abc.def.ghi"},
                         {"private_key", "-----BEGIN PRIVATE KEY-----"},
                         {"db_password", "password-secret"}};
    e.payload_json = payload.dump();
    const auto mapped = FilesAuditMapper::to_validated_proto(e);
    ASSERT_TRUE(mapped.valid) << mapped.validation_error;
    const auto serialized = mapped.proto.SerializeAsString();
    for (const auto secret : {"secret-report.pdf", "nonce-secret", "tag-secret", "key-secret", "s3-secret",
                              "abc.def.ghi", "BEGIN PRIVATE KEY", "password-secret"}) {
        EXPECT_EQ(serialized.find(secret), std::string::npos) << secret;
    }
}

TEST(FilesOutboxAuditTest, AuthAuditHeaderAndFilesAuditValidatorFacadeCanShareTranslationUnit) {
    const auto auth_type = securecloud::auth::domain::AuditEventType::LoginSucceeded;
    EXPECT_EQ(securecloud::auth::domain::to_string(auth_type), "auth.login.succeeded");
    const auto entity_value = entity("file.created");
    const auto mapped = FilesAuditMapper::to_validated_proto(entity_value);
    EXPECT_TRUE(mapped.valid) << mapped.validation_error;
}

TEST(FilesOutboxAuditTest, PromotesChunkIntegrityToSecurityAndMapsFileFinalizing) {
    FilesAuditProtoValidator validator;
    const auto now = std::chrono::system_clock::now();

    for (const auto& [outbox_sev, payload_sev] : std::array<std::pair<OutboxSeverity, std::string>, 2>{
             {{OutboxSeverity::Info, "INFO"}, {OutboxSeverity::Warning, "WARNING"}}}) {
        auto e = entity("file.chunk.integrity_failed");
        e.severity = outbox_sev;
        auto payload = nlohmann::json::parse(e.payload_json);
        payload["severity"] = payload_sev;
        e.payload_json = payload.dump();

        const auto mapped = FilesAuditMapper::to_validated_proto(e, now, "files-test");
        ASSERT_TRUE(mapped.valid) << mapped.validation_error;
        EXPECT_EQ(mapped.proto.severity(), securecloud::audit::v1::SEVERITY_SECURITY);
        EXPECT_TRUE(validator.validate(mapped.proto, now).valid);
    }

    auto finalizing = FilesAuditMapper::to_validated_proto(entity("FILE_FINALIZING"), now, "files-test");
    ASSERT_TRUE(finalizing.valid) << finalizing.validation_error;
    EXPECT_EQ(finalizing.proto.event_type(), "file.upload.completed");
    EXPECT_TRUE(validator.validate(finalizing.proto, now).valid);
}
} // namespace securecloud::files::audit
