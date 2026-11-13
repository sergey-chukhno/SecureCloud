#pragma once

#include "messaging/repository/messaging_audit_outbox_repository_interface.hpp"

#include <chrono>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <tuple>

namespace securecloud::messaging::repository {

/// Thread-safe in-memory implementation of IMessagingAuditOutboxRepository for hermetic unit testing.
class InMemoryMessagingAuditOutboxRepository : public IMessagingAuditOutboxRepository {
  public:
    using ClockFn = std::function<std::chrono::system_clock::time_point()>;

    explicit InMemoryMessagingAuditOutboxRepository(
        ClockFn clock_fn = []() { return std::chrono::system_clock::now(); });

    void enqueue_audit_event(const AuditOutboxRecord& record) override;

    [[nodiscard]] std::vector<AuditOutboxRecord> fetch_pending_events(const std::string& outbox_bucket,
                                                                      int32_t shard_id, size_t limit,
                                                                      std::chrono::seconds lease_duration) override;

    void mark_published(const std::string& outbox_bucket, int32_t shard_id,
                        const std::chrono::system_clock::time_point& created_at,
                        const std::string& event_id) override;

    void record_failure(const std::string& outbox_bucket, int32_t shard_id,
                        const std::chrono::system_clock::time_point& created_at, const std::string& event_id,
                        const std::string& error_message, bool should_quarantine) override;

    [[nodiscard]] size_t count_pending_backlog(const std::string& outbox_bucket, int32_t shard_id) override;

    // --- Test Inspection Helpers ---
    [[nodiscard]] std::optional<AuditOutboxRecord> find_record(const std::string& outbox_bucket, int32_t shard_id,
                                                               const std::chrono::system_clock::time_point& created_at,
                                                               const std::string& event_id) const;

    [[nodiscard]] size_t total_records() const;

  private:
    // Ordered by (outbox_bucket, shard_id, created_at_ms, event_id) to mirror ScyllaDB clustering order
    using PrimaryKey = std::tuple<std::string, int32_t, int64_t, std::string>;

    ClockFn clock_fn_;
    mutable std::mutex mutex_;
    std::map<PrimaryKey, AuditOutboxRecord> records_;
};

} // namespace securecloud::messaging::repository
