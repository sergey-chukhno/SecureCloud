#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace securecloud::messaging::repository {

struct AuditOutboxRecord {
    std::string outbox_bucket;
    int32_t shard_id{0};
    std::chrono::system_clock::time_point created_at{};
    std::string event_id;
    std::string event_type;
    std::string severity;
    std::string actor_user_id;
    std::string actor_device_id;
    std::string target_resource;
    std::vector<uint8_t> payload_proto_bin;
    std::string publish_status{"PENDING"}; // "PENDING", "PUBLISHED", "QUARANTINED"
    int32_t attempt_count{0};
    std::chrono::system_clock::time_point last_attempt_at{};
    std::string last_error;
    std::chrono::system_clock::time_point leased_until{};

    bool operator==(const AuditOutboxRecord& other) const noexcept = default;
};

class IMessagingAuditOutboxRepository {
  public:
    virtual ~IMessagingAuditOutboxRepository() = default;

    virtual void enqueue_audit_event(const AuditOutboxRecord& record) = 0;

    virtual std::vector<AuditOutboxRecord> fetch_pending_events(const std::string& outbox_bucket, int32_t shard_id,
                                                                size_t limit, std::chrono::seconds lease_duration) = 0;

    virtual void mark_published(const std::string& outbox_bucket, int32_t shard_id,
                                const std::chrono::system_clock::time_point& created_at,
                                const std::string& event_id) = 0;

    virtual void record_failure(const std::string& outbox_bucket, int32_t shard_id,
                                const std::chrono::system_clock::time_point& created_at, const std::string& event_id,
                                const std::string& error_message, bool should_quarantine) = 0;

    virtual size_t count_pending_backlog(const std::string& outbox_bucket, int32_t shard_id) = 0;
};

} // namespace securecloud::messaging::repository
