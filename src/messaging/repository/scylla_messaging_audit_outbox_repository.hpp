#pragma once

#include "messaging/db/scylla_session_interface.hpp"
#include "messaging/repository/messaging_audit_outbox_repository_interface.hpp"

#include <chrono>
#include <functional>
#include <memory>
#include <mutex>

namespace securecloud::messaging::repository {

/// ScyllaDB persistence adapter for the sharded Messaging Audit Outbox (ADR-012, AUDIT-014).
/// Table: securecloud_messaging.messaging_audit_outbox
/// - Partition Key: ((outbox_bucket, shard_id))
/// - Clustering Key: created_at ASC, event_id ASC
class ScyllaMessagingAuditOutboxRepository : public IMessagingAuditOutboxRepository {
  public:
    using ClockFn = std::function<std::chrono::system_clock::time_point()>;

    explicit ScyllaMessagingAuditOutboxRepository(
        std::shared_ptr<db::IScyllaSession> session,
        ClockFn clock_fn = []() { return std::chrono::system_clock::now(); });

    void enqueue_audit_event(const AuditOutboxRecord& record) override;

    [[nodiscard]] std::vector<AuditOutboxRecord> fetch_pending_events(const std::string& outbox_bucket,
                                                                      int32_t shard_id, size_t limit,
                                                                      std::chrono::seconds lease_duration) override;

    void mark_published(const std::string& outbox_bucket, int32_t shard_id,
                        const std::chrono::system_clock::time_point& created_at, const std::string& event_id) override;

    void record_failure(const std::string& outbox_bucket, int32_t shard_id,
                        const std::chrono::system_clock::time_point& created_at, const std::string& event_id,
                        const std::string& error_message, bool should_quarantine) override;

    [[nodiscard]] size_t count_pending_backlog(const std::string& outbox_bucket, int32_t shard_id) override;

    [[nodiscard]] bool has_event(const std::string& outbox_bucket, int32_t shard_id,
                                 const std::chrono::system_clock::time_point& created_at,
                                 const std::string& event_id) override;

  private:
    void init_prepared_statements();

    std::shared_ptr<db::IScyllaSession> session_;
    ClockFn clock_fn_;
    mutable std::mutex mutex_;

    db::PreparedStatementId prep_enqueue_event_;
    db::PreparedStatementId prep_fetch_pending_;
    db::PreparedStatementId prep_lease_event_;
    db::PreparedStatementId prep_mark_published_;
    db::PreparedStatementId prep_select_attempt_count_;
    db::PreparedStatementId prep_record_failure_;
    db::PreparedStatementId prep_count_pending_;
};

} // namespace securecloud::messaging::repository
