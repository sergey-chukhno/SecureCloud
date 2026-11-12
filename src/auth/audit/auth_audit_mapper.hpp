#pragma once

#include "auth/auth_config.hpp"
#include "auth/domain/auth_outbox_entity.hpp"
#include "securecloud/audit/v1/audit.pb.h"

#include <string>
#include <string_view>

namespace securecloud::auth::audit {

/// Canonical mapper translating persistent AuthOutboxEntity records into validated,
/// secret-sanitized AuditEventProto messages conforming to AUDIT-002.
class AuthAuditMapper {
  public:
    explicit AuthAuditMapper(std::string default_producer_instance = "auth");
    explicit AuthAuditMapper(const AuthConfig& config);

    /// Translates an AuthOutboxEntity into a wire AuditEventProto using the configured producer instance.
    /// Throws std::invalid_argument or std::runtime_error if validation fails.
    [[nodiscard]] ::securecloud::audit::v1::AuditEventProto map(const domain::AuthOutboxEntity& entity) const;

    /// Stateless translation entry point.
    [[nodiscard]] static ::securecloud::audit::v1::AuditEventProto
    to_proto(const domain::AuthOutboxEntity& entity, std::string_view default_producer_instance = "auth");

    /// Returns true if a metadata key name matches forbidden secret/credential patterns.
    [[nodiscard]] static bool is_sensitive_metadata_key(std::string_view key) noexcept;

    /// Redacts secret-like values (JWTs, Bearer tokens, PEM private keys, password hashes).
    [[nodiscard]] static std::string sanitize_metadata_value(std::string_view value);

  private:
    std::string default_producer_instance_;
};

} // namespace securecloud::auth::audit
