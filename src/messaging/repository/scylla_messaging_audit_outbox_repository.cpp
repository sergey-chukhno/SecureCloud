#include "messaging/repository/scylla_messaging_audit_outbox_repository.hpp"

#include "domain/audit_event.hpp"
#include "util/zero_plaintext_guard.hpp"

#include <algorithm>
#include <stdexcept>

namespace securecloud::messaging::repository {
namespace {

inline int64_t to_millis(std::chrono::system_clock::time_point tp) noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
}

inline std::chrono::system_clock::time_point from_millis(int64_t ms) noexcept {
    return std::chrono::system_clock::time_point(std::chrono::milliseconds(ms));
}

void validate_partition_coords(const std::string& outbox_bucket, int32_t shard_id) {
    if (outbox_bucket.empty()) {
        throw std::invalid_argument("AuditOutboxRecord outbox_bucket must not be empty");
    }
    if (shard_id < 0 || shard_id >= domain::kMessagingAuditOutboxShardCount) {
        throw std::invalid_argument("AuditOutboxRecord shard_id must be in [0, 15]");
    }
}

AuditOutboxRecord row_to_audit_outbox_record(const db::ScyllaRow& row) {
    AuditOutboxRecord record;
    record.outbox_bucket = row.get_string("outbox_bucket");
    record.shard_id = row.get_int("shard_id");
    record.created_at = from_millis(row.get_timestamp("created_at"));
    record.event_id = row.get_string("event_id");
    record.event_type = row.get_string("event_type");
    record.severity = row.get_string("severity");

    if (!row.is_null("actor_user_id")) {
        record.actor_user_id = row.get_string("actor_user_id");
    }
    if (!row.is_null("actor_device_id")) {
        record.actor_device_id = row.get_string("actor_device_id");
    }
    if (!row.is_null("target_resource")) {
        record.target_resource = row.get_string("target_resource");
    }
    if (!row.is_null("payload_proto_bin")) {
        record.payload_proto_bin = row.get_blob("payload_proto_bin");
    }

    record.publish_status = row.is_null("publish_status") ? "PENDING" : row.get_string("publish_status");
    record.attempt_count = row.is_null("attempt_count") ? 0 : row.get_int("attempt_count");

    if (!row.is_null("last_attempt_at")) {
        record.last_attempt_at = from_millis(row.get_timestamp("last_attempt_at"));
    }
    if (!row.is_null("last_error")) {
        record.last_error = row.get_string("last_error");
    }
    if (!row.is_null("leased_until")) {
        record.leased_until = from_millis(row.get_timestamp("leased_until"));
    }

    return record;
}

} // namespace

ScyllaMessagingAuditOutboxRepository::ScyllaMessagingAuditOutboxRepository(std::shared_ptr<db::IScyllaSession> session,
                                                                           ClockFn clock_fn)
    : session_(std::move(session)), clock_fn_(std::move(clock_fn)) {
    if (!session_) {
        throw std::invalid_argument("ScyllaMessagingAuditOutboxRepository requires non-null IScyllaSession");
    }
    if (!clock_fn_) {
        clock_fn_ = []() { return std::chrono::system_clock::now(); };
    }
    init_prepared_statements();
}

void ScyllaMessagingAuditOutboxRepository::init_prepared_statements() {
    prep_enqueue_event_ = session_->prepare("audit_outbox_enqueue",
                                            "INSERT INTO securecloud_messaging.messaging_audit_outbox "
                                            "(outbox_bucket, shard_id, created_at, event_id, event_type, severity, "
                                            "actor_user_id, actor_device_id, target_resource, payload_proto_bin, "
                                            "publish_status, attempt_count, last_attempt_at, last_error, leased_until) "
                                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");

    prep_fetch_pending_ = session_->prepare(
        "audit_outbox_fetch_pending", "SELECT outbox_bucket, shard_id, created_at, event_id, event_type, severity, "
                                      "actor_user_id, actor_device_id, target_resource, payload_proto_bin, "
                                      "publish_status, attempt_count, last_attempt_at, last_error, leased_until "
                                      "FROM securecloud_messaging.messaging_audit_outbox "
                                      "WHERE outbox_bucket = ? AND shard_id = ? AND publish_status = 'PENDING' "
                                      "LIMIT ? ALLOW FILTERING;");

    prep_lease_event_ = session_->prepare(
        "audit_outbox_lease_event", "UPDATE securecloud_messaging.messaging_audit_outbox "
                                    "SET leased_until = ? "
                                    "WHERE outbox_bucket = ? AND shard_id = ? AND created_at = ? AND event_id = ?;");

    prep_mark_published_ = session_->prepare(
        "audit_outbox_mark_published", "UPDATE securecloud_messaging.messaging_audit_outbox "
                                       "SET publish_status = 'PUBLISHED', leased_until = null "
                                       "WHERE outbox_bucket = ? AND shard_id = ? AND created_at = ? AND event_id = ?;");

    prep_select_attempt_count_ =
        session_->prepare("audit_outbox_select_attempts",
                          "SELECT attempt_count FROM securecloud_messaging.messaging_audit_outbox "
                          "WHERE outbox_bucket = ? AND shard_id = ? AND created_at = ? AND event_id = ?;");

    prep_record_failure_ = session_->prepare(
        "audit_outbox_record_failure",
        "UPDATE securecloud_messaging.messaging_audit_outbox "
        "SET publish_status = ?, attempt_count = ?, last_attempt_at = ?, last_error = ?, leased_until = null "
        "WHERE outbox_bucket = ? AND shard_id = ? AND created_at = ? AND event_id = ?;");

    prep_count_pending_ =
        session_->prepare("audit_outbox_count_pending",
                          "SELECT COUNT(*) AS pending_count FROM securecloud_messaging.messaging_audit_outbox "
                          "WHERE outbox_bucket = ? AND shard_id = ? AND publish_status = 'PENDING' ALLOW FILTERING;");
}

void ScyllaMessagingAuditOutboxRepository::enqueue_audit_event(const AuditOutboxRecord& record) {
    validate_partition_coords(record.outbox_bucket, record.shard_id);
    if (record.event_id.empty()) {
        throw std::invalid_argument("AuditOutboxRecord event_id must not be empty");
    }
    if (record.event_type.empty()) {
        throw std::invalid_argument("AuditOutboxRecord event_type must not be empty");
    }

    std::lock_guard<std::mutex> lock(mutex_);

    const std::string status = record.publish_status.empty() ? "PENDING" : record.publish_status;

    db::ScyllaParams params;
    params.add_string(record.outbox_bucket);
    params.add_int(record.shard_id);
    params.add_timestamp(to_millis(record.created_at));
    params.add_string(record.event_id);
    params.add_string(record.event_type);
    params.add_string(record.severity.empty() ? "INFO" : record.severity);
    params.add_string(record.actor_user_id);
    params.add_string(record.actor_device_id);
    params.add_string(record.target_resource);
    params.add_blob(record.payload_proto_bin);
    params.add_string(status);
    params.add_int(record.attempt_count);

    if (record.last_attempt_at.time_since_epoch().count() > 0) {
        params.add_timestamp(to_millis(record.last_attempt_at));
    } else {
        params.add_null();
    }

    if (!record.last_error.empty()) {
        params.add_string(util::ZeroPlaintextGuard::sanitize_error_message(record.last_error));
    } else {
        params.add_null();
    }

    if (record.leased_until.time_since_epoch().count() > 0) {
        params.add_timestamp(to_millis(record.leased_until));
    } else {
        params.add_null();
    }

    session_->execute_prepared(prep_enqueue_event_, params, db::ConsistencyLevel::LocalQuorum);
}

std::vector<AuditOutboxRecord>
ScyllaMessagingAuditOutboxRepository::fetch_pending_events(const std::string& outbox_bucket, int32_t shard_id,
                                                           size_t limit, std::chrono::seconds lease_duration) {
    validate_partition_coords(outbox_bucket, shard_id);
    if (limit == 0) {
        return {};
    }

    std::lock_guard<std::mutex> lock(mutex_);

    const auto now = clock_fn_();
    // Over-fetch slightly to skip currently leased rows while still bounding partition scan
    const int32_t fetch_limit = static_cast<int32_t>(std::min<size_t>(limit * 2, 1000));

    db::ScyllaParams fetch_params;
    fetch_params.add_string(outbox_bucket);
    fetch_params.add_int(shard_id);
    fetch_params.add_int(fetch_limit);

    const auto result =
        session_->execute_prepared(prep_fetch_pending_, fetch_params, db::ConsistencyLevel::LocalQuorum);

    const auto lease_expiry = now + lease_duration;
    const int64_t lease_expiry_ms = to_millis(lease_expiry);

    std::vector<AuditOutboxRecord> claimed;
    claimed.reserve(std::min(limit, result.size()));

    for (const auto& row : result) {
        if (claimed.size() >= limit) {
            break;
        }
        AuditOutboxRecord record = row_to_audit_outbox_record(row);
        if (record.publish_status != "PENDING") {
            continue;
        }
        // Skip records with an active unexpired lease held by another worker
        if (record.leased_until.time_since_epoch().count() > 0 && record.leased_until > now) {
            continue;
        }

        db::ScyllaParams lease_params;
        lease_params.add_timestamp(lease_expiry_ms);
        lease_params.add_string(record.outbox_bucket);
        lease_params.add_int(record.shard_id);
        lease_params.add_timestamp(to_millis(record.created_at));
        lease_params.add_string(record.event_id);

        session_->execute_prepared(prep_lease_event_, lease_params, db::ConsistencyLevel::LocalQuorum);

        record.leased_until = lease_expiry;
        claimed.push_back(std::move(record));
    }

    return claimed;
}

void ScyllaMessagingAuditOutboxRepository::mark_published(const std::string& outbox_bucket, int32_t shard_id,
                                                          const std::chrono::system_clock::time_point& created_at,
                                                          const std::string& event_id) {
    validate_partition_coords(outbox_bucket, shard_id);
    if (event_id.empty()) {
        throw std::invalid_argument("mark_published requires non-empty event_id");
    }

    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(outbox_bucket);
    params.add_int(shard_id);
    params.add_timestamp(to_millis(created_at));
    params.add_string(event_id);

    session_->execute_prepared(prep_mark_published_, params, db::ConsistencyLevel::LocalQuorum);
}

void ScyllaMessagingAuditOutboxRepository::record_failure(const std::string& outbox_bucket, int32_t shard_id,
                                                          const std::chrono::system_clock::time_point& created_at,
                                                          const std::string& event_id, const std::string& error_message,
                                                          bool should_quarantine) {
    validate_partition_coords(outbox_bucket, shard_id);
    if (event_id.empty()) {
        throw std::invalid_argument("record_failure requires non-empty event_id");
    }

    std::lock_guard<std::mutex> lock(mutex_);

    const int64_t created_at_ms = to_millis(created_at);

    db::ScyllaParams select_params;
    select_params.add_string(outbox_bucket);
    select_params.add_int(shard_id);
    select_params.add_timestamp(created_at_ms);
    select_params.add_string(event_id);

    int32_t current_attempts = 0;
    const auto existing =
        session_->execute_prepared(prep_select_attempt_count_, select_params, db::ConsistencyLevel::LocalQuorum);
    if (!existing.empty() && existing.front().has_column("attempt_count") &&
        !existing.front().is_null("attempt_count")) {
        current_attempts = existing.front().get_int("attempt_count");
    }

    const std::string next_status = should_quarantine ? "QUARANTINED" : "PENDING";
    const std::string sanitized_err = util::ZeroPlaintextGuard::sanitize_error_message(error_message);
    const int64_t now_ms = to_millis(clock_fn_());

    db::ScyllaParams update_params;
    update_params.add_string(next_status);
    update_params.add_int(current_attempts + 1);
    update_params.add_timestamp(now_ms);
    update_params.add_string(sanitized_err);
    update_params.add_string(outbox_bucket);
    update_params.add_int(shard_id);
    update_params.add_timestamp(created_at_ms);
    update_params.add_string(event_id);

    session_->execute_prepared(prep_record_failure_, update_params, db::ConsistencyLevel::LocalQuorum);
}

size_t ScyllaMessagingAuditOutboxRepository::count_pending_backlog(const std::string& outbox_bucket, int32_t shard_id) {
    validate_partition_coords(outbox_bucket, shard_id);

    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(outbox_bucket);
    params.add_int(shard_id);

    const auto result = session_->execute_prepared(prep_count_pending_, params, db::ConsistencyLevel::LocalQuorum);
    if (result.empty()) {
        return 0;
    }

    const auto& first_row = result.front();
    if (first_row.has_column("pending_count") && !first_row.is_null("pending_count")) {
        const int64_t count = first_row.get_int64("pending_count");
        return count > 0 ? static_cast<size_t>(count) : 0U;
    }
    if (first_row.has_column("count") && !first_row.is_null("count")) {
        const int64_t count = first_row.get_int64("count");
        return count > 0 ? static_cast<size_t>(count) : 0U;
    }

    size_t pending_rows = 0;
    for (const auto& row : result) {
        if (!row.has_column("publish_status") || row.get_string("publish_status") == "PENDING") {
            ++pending_rows;
        }
    }
    return pending_rows;
}

bool ScyllaMessagingAuditOutboxRepository::has_event(const std::string& outbox_bucket, int32_t shard_id,
                                                     const std::chrono::system_clock::time_point& created_at,
                                                     const std::string& event_id) {
    validate_partition_coords(outbox_bucket, shard_id);
    if (event_id.empty()) {
        throw std::invalid_argument("has_event requires non-empty event_id");
    }

    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(outbox_bucket);
    params.add_int(shard_id);
    params.add_timestamp(to_millis(created_at));
    params.add_string(event_id);

    const auto existing =
        session_->execute_prepared(prep_select_attempt_count_, params, db::ConsistencyLevel::LocalQuorum);
    return !existing.empty();
}

} // namespace securecloud::messaging::repository
