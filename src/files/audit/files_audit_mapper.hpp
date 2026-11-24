#pragma once

#include "files/domain/files_outbox_entity.hpp"
#include "securecloud/audit/v1/audit.pb.h"

#include <chrono>
#include <string>
#include <string_view>

namespace securecloud::files::audit {

struct MappedAuditEvent {
    securecloud::audit::v1::AuditEventProto proto;
    bool valid{false};
    std::string validation_error;
};

/**
 * @brief Canonical AUDIT-002 Proto Mapper & Stage-2 Zero-Secret / Zero-Filename Scrubber.
 *
 * Enforces:
 * - Rolling-upgrade `FILE_*` -> `file.*` event type normalization
 * - Explicit producer, severity, actor, target, UUIDv7 event_id, and correlation_id mapping
 * - Two-stage sanitization stripping forbidden keys, nested objects, oversized fields,
 *   Bearer tokens, PEM private keys, Argon2id/bcrypt hashes, and 3-segment JWTs
 * - Pre-flight validation against `AuditEventValidator` before gRPC dispatch
 */
class FilesAuditMapper {
  public:
    static constexpr std::string_view k_default_producer_instance = "files-service";
    static constexpr std::size_t k_max_metadata_entries = 50;
    static constexpr std::size_t k_max_metadata_key_length = 64;
    static constexpr std::size_t k_max_metadata_value_length = 1024;
    static constexpr std::size_t k_max_id_length = 64;

    /**
     * @brief Translates a single FilesOutboxEntity to a canonical AuditEventProto message.
     */
    [[nodiscard]] static securecloud::audit::v1::AuditEventProto
    to_proto(const FilesOutboxEntity& entity, std::string_view producer_instance = k_default_producer_instance);

    /**
     * @brief Translates and pre-flight validates an outbox entity against AuditEventValidator.
     *        Invalid rows are flagged so the relay can quarantine them locally before gRPC dispatch.
     */
    [[nodiscard]] static MappedAuditEvent
    to_validated_proto(const FilesOutboxEntity& entity,
                       std::chrono::system_clock::time_point now = std::chrono::system_clock::now(),
                       std::string_view producer_instance = k_default_producer_instance);
};

} // namespace securecloud::files::audit
