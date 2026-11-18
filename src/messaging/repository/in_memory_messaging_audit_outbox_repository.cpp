#include "messaging/repository/in_memory_messaging_audit_outbox_repository.hpp"

#include "domain/audit_event.hpp"
#include "util/zero_plaintext_guard.hpp"

#include <stdexcept>

namespace securecloud::messaging::repository {
namespace {

inline int64_t to_millis(std::chrono::system_clock::time_point tp) noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
}

} // namespace

InMemoryMessagingAuditOutboxRepository::InMemoryMessagingAuditOutboxRepository(ClockFn clock_fn)
    : clock_fn_(std::move(clock_fn)) {
    if (!clock_fn_) {
        clock_fn_ = []() { return std::chrono::system_clock::now(); };
    }
}

void InMemoryMessagingAuditOutboxRepository::enqueue_audit_event(const AuditOutboxRecord& record) {
    if (record.outbox_bucket.empty()) {
        throw std::invalid_argument("AuditOutboxRecord outbox_bucket must not be empty");
    }
    if (record.shard_id < 0 || record.shard_id >= domain::kMessagingAuditOutboxShardCount) {
        throw std::invalid_argument("AuditOutboxRecord shard_id must be in [0, 15]");
    }
    if (record.event_id.empty()) {
        throw std::invalid_argument("AuditOutboxRecord event_id must not be empty");
    }

    std::lock_guard<std::mutex> lock(mutex_);

    AuditOutboxRecord stored = record;
    if (stored.publish_status.empty()) {
        stored.publish_status = "PENDING";
    }
    if (!stored.last_error.empty()) {
        stored.last_error = util::ZeroPlaintextGuard::sanitize_error_message(stored.last_error);
    }

    PrimaryKey pk{stored.outbox_bucket, stored.shard_id, to_millis(stored.created_at), stored.event_id};
    records_[std::move(pk)] = std::move(stored);
}

std::vector<AuditOutboxRecord>
InMemoryMessagingAuditOutboxRepository::fetch_pending_events(const std::string& outbox_bucket, int32_t shard_id,
                                                             size_t limit, std::chrono::seconds lease_duration) {
    if (limit == 0) {
        return {};
    }

    std::lock_guard<std::mutex> lock(mutex_);

    const auto now = clock_fn_();
    const auto lease_expiry = now + lease_duration;
    std::vector<AuditOutboxRecord> claimed;

    for (auto& [pk, record] : records_) {
        if (claimed.size() >= limit) {
            break;
        }
        if (record.outbox_bucket != outbox_bucket || record.shard_id != shard_id) {
            continue;
        }
        if (record.publish_status != "PENDING") {
            continue;
        }
        if (record.leased_until.time_since_epoch().count() > 0 && record.leased_until > now) {
            continue;
        }

        record.leased_until = lease_expiry;
        claimed.push_back(record);
    }

    return claimed;
}

void InMemoryMessagingAuditOutboxRepository::mark_published(const std::string& outbox_bucket, int32_t shard_id,
                                                            const std::chrono::system_clock::time_point& created_at,
                                                            const std::string& event_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    PrimaryKey pk{outbox_bucket, shard_id, to_millis(created_at), event_id};
    auto it = records_.find(pk);
    if (it != records_.end()) {
        it->second.publish_status = "PUBLISHED";
        it->second.leased_until = std::chrono::system_clock::time_point{};
    }
}

void InMemoryMessagingAuditOutboxRepository::record_failure(const std::string& outbox_bucket, int32_t shard_id,
                                                            const std::chrono::system_clock::time_point& created_at,
                                                            const std::string& event_id,
                                                            const std::string& error_message, bool should_quarantine) {
    std::lock_guard<std::mutex> lock(mutex_);

    PrimaryKey pk{outbox_bucket, shard_id, to_millis(created_at), event_id};
    auto it = records_.find(pk);
    if (it != records_.end()) {
        it->second.attempt_count += 1;
        it->second.last_attempt_at = clock_fn_();
        it->second.last_error = util::ZeroPlaintextGuard::sanitize_error_message(error_message);
        it->second.publish_status = should_quarantine ? "QUARANTINED" : "PENDING";
        it->second.leased_until = std::chrono::system_clock::time_point{};
    }
}

size_t InMemoryMessagingAuditOutboxRepository::count_pending_backlog(const std::string& outbox_bucket,
                                                                     int32_t shard_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t count = 0;
    for (const auto& [pk, record] : records_) {
        if (record.outbox_bucket == outbox_bucket && record.shard_id == shard_id &&
            record.publish_status == "PENDING") {
            ++count;
        }
    }
    return count;
}

std::optional<AuditOutboxRecord>
InMemoryMessagingAuditOutboxRepository::find_record(const std::string& outbox_bucket, int32_t shard_id,
                                                    const std::chrono::system_clock::time_point& created_at,
                                                    const std::string& event_id) const {
    std::lock_guard<std::mutex> lock(mutex_);

    PrimaryKey pk{outbox_bucket, shard_id, to_millis(created_at), event_id};
    auto it = records_.find(pk);
    if (it == records_.end()) {
        return std::nullopt;
    }
    return it->second;
}

size_t InMemoryMessagingAuditOutboxRepository::total_records() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return records_.size();
}

} // namespace securecloud::messaging::repository
