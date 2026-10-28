#include <gtest/gtest.h>

#include "files/audit/files_audit_mapper.hpp"
#include "files/domain/files_outbox_entity.hpp"

#include <chrono>
#include <nlohmann/json.hpp>

namespace securecloud::files::audit {

TEST(FilesAuditMapperTest, MapsFileCreatedEventSuccessfully) {
    FilesOutboxEntity entity;
    entity.event_id = "evt-12345";
    entity.aggregate_id = "file-abcde";
    entity.event_type = "FILE_CREATED";
    entity.created_at = std::chrono::system_clock::now();

    nlohmann::json payload;
    payload["owner_user_id"] = "usr-owner-99";
    payload["request_id"] = "req-corr-777";
    payload["file_size"] = 1048576;
    payload["mime_type"] = "application/octet-stream";
    payload["is_active"] = true;
    entity.payload_json = payload.dump();

    auto proto = FilesAuditMapper::to_proto(entity);

    EXPECT_EQ(proto.event_id(), "evt-12345");
    EXPECT_EQ(proto.event_type(), "FILE_CREATED");
    EXPECT_EQ(proto.producer_service(), securecloud::audit::v1::ProducerServiceProto::PRODUCER_SERVICE_FILES);
    EXPECT_EQ(proto.producer_instance(), "files-daemon");
    EXPECT_EQ(proto.target_type(), securecloud::audit::v1::TargetTypeProto::TARGET_TYPE_FILE);
    EXPECT_EQ(proto.target_id(), "file-abcde");
    EXPECT_EQ(proto.actor_type(), securecloud::audit::v1::ActorTypeProto::ACTOR_TYPE_USER);
    EXPECT_EQ(proto.actor_id(), "usr-owner-99");
    EXPECT_EQ(proto.correlation_id(), "req-corr-777");
    EXPECT_EQ(proto.severity(), securecloud::audit::v1::SeverityProto::SEVERITY_INFO);

    const auto& meta = proto.metadata();
    EXPECT_EQ(meta.at("mime_type"), "application/octet-stream");
    EXPECT_EQ(meta.at("file_size"), "1048576");
    EXPECT_EQ(meta.at("is_active"), "true");
}

TEST(FilesAuditMapperTest, ZeroPlaintextGuaranteeFiltersSensitiveKeys) {
    FilesOutboxEntity entity;
    entity.event_id = "evt-sec-1";
    entity.aggregate_id = "file-999";
    entity.event_type = "FILE_FINALIZED";
    entity.created_at = std::chrono::system_clock::now();

    nlohmann::json payload;
    payload["user_id"] = "usr-alice";
    payload["safe_key"] = "safe_value";
    // Dangerous sensitive keys
    payload["encryption_key"] = "SUPER_SECRET_AES_KEY";
    payload["key"] = "LEAKED_KEY";
    payload["secret"] = "SECRET_TOKEN";
    payload["token"] = "BEARER_AUTH_TOKEN";
    payload["ciphertext"] = "RAW_CIPHERTEXT_BYTES";
    payload["data"] = "RAW_PLAINTEXT_BYTES";
    payload["encrypted_data"] = "ENCRYPTED_BLOB";
    payload["password"] = "PASSWORD123";
    entity.payload_json = payload.dump();

    auto proto = FilesAuditMapper::to_proto(entity);

    const auto& meta = proto.metadata();
    EXPECT_EQ(meta.at("safe_key"), "safe_value");
    EXPECT_EQ(meta.find("encryption_key"), meta.end());
    EXPECT_EQ(meta.find("key"), meta.end());
    EXPECT_EQ(meta.find("secret"), meta.end());
    EXPECT_EQ(meta.find("token"), meta.end());
    EXPECT_EQ(meta.find("ciphertext"), meta.end());
    EXPECT_EQ(meta.find("data"), meta.end());
    EXPECT_EQ(meta.find("encrypted_data"), meta.end());
    EXPECT_EQ(meta.find("password"), meta.end());
}

TEST(FilesAuditMapperTest, SecuritySeverityForRevocationEvents) {
    FilesOutboxEntity entity;
    entity.event_id = "evt-rev-1";
    entity.aggregate_id = "file-101";
    entity.event_type = "FILE_ACCESS_REVOKED";
    entity.created_at = std::chrono::system_clock::now();
    entity.payload_json = "{}";

    auto proto = FilesAuditMapper::to_proto(entity);
    EXPECT_EQ(proto.severity(), securecloud::audit::v1::SeverityProto::SEVERITY_SECURITY);

    entity.event_type = "CAPABILITY_REJECTED";
    auto proto2 = FilesAuditMapper::to_proto(entity);
    EXPECT_EQ(proto2.severity(), securecloud::audit::v1::SeverityProto::SEVERITY_SECURITY);
}

TEST(FilesAuditMapperTest, HandlesMalformedPayloadGracefully) {
    FilesOutboxEntity entity;
    entity.event_id = "evt-bad-json";
    entity.aggregate_id = "file-err";
    entity.event_type = "FILE_ERROR";
    entity.created_at = std::chrono::system_clock::now();
    entity.payload_json = "{bad_json: invalid";

    auto proto = FilesAuditMapper::to_proto(entity);
    EXPECT_EQ(proto.event_id(), "evt-bad-json");
    EXPECT_EQ(proto.correlation_id(), "evt-bad-json");
    EXPECT_EQ(proto.actor_id(), "system");
    EXPECT_EQ(proto.actor_type(), securecloud::audit::v1::ActorTypeProto::ACTOR_TYPE_SYSTEM);
}

} // namespace securecloud::files::audit
