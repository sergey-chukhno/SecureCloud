#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_local_store.hpp"
#include "domain/local_audit_event.hpp"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::application::managers {

/// Manages strictly endpoint-local tamper-evident audit logging (`local_audit_log` in SQLCipher).
/// Sanitizes all inputs through ClientLogger::sanitize() prior to canonical hashing so secrets,
/// tokens, recovery digests, key material, plaintext messages, and PII never hit disk.
class LocalAuditLogger {
  public:
    explicit LocalAuditLogger(interfaces::ILocalStore& local_store);
    ~LocalAuditLogger() = default;

    LocalAuditLogger(const LocalAuditLogger&) = delete;
    LocalAuditLogger& operator=(const LocalAuditLogger&) = delete;

    [[nodiscard]] ClientResult<domain::LocalAuditEvent>
    record_event(domain::LocalAuditCategory category, std::string_view event_type, domain::LocalAuditOutcome outcome,
                 std::string_view actor_opaque_id, std::string_view target_opaque_id, std::string_view raw_summary,
                 int64_t occurred_at_ms = 0);

    [[nodiscard]] ClientResult<domain::AuditChainVerificationResult> verify_chain_integrity() const;

    [[nodiscard]] ClientResult<std::vector<domain::LocalAuditEvent>> recent_events(std::size_t limit = 100U) const;

    [[nodiscard]] ClientResult<std::size_t> event_count() const;

    void wipe_volatile_state() noexcept;

  private:
    [[nodiscard]] ClientResult<void> refresh_head_locked();

    interfaces::ILocalStore& local_store_;
    mutable std::mutex mutex_;
    bool initialized_{false};
    int64_t last_sequence_id_{0};
    std::string last_hash_sha256_{domain::kGenesisAuditHash};
};

} // namespace securecloud::client::application::managers
