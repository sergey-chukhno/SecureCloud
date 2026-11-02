#pragma once

#include "files/domain/files_outbox_entity.hpp"
#include "securecloud/audit/v1/audit.pb.h"

namespace securecloud::files::audit {

/**
 * @brief Maps transactional outbox entities to standardized AuditEventProto messages.
 *
 * Enforces Zero-Plaintext and Secret Isolation invariants:
 * NEVER maps encryption keys, plaintext filenames, or ciphertext bytes into audit metadata.
 */
class FilesAuditMapper {
  public:
    /**
     * @brief Translates a single FilesOutboxEntity to an AuditEventProto message.
     */
    [[nodiscard]] static securecloud::audit::v1::AuditEventProto to_proto(const FilesOutboxEntity& entity);
};

} // namespace securecloud::files::audit
