#include "messaging/repository/scylla_outbox_repository.hpp"

#include <chrono>
#include <stdexcept>

namespace securecloud::messaging::repository {
namespace {

inline int64_t to_millis(std::chrono::system_clock::time_point tp) noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
}

inline std::chrono::system_clock::time_point from_millis(int64_t ms) noexcept {
    return std::chrono::system_clock::time_point(std::chrono::milliseconds(ms));
}

OutboxEventRecord row_to_outbox_record(const db::ScyllaRow& row) {
    OutboxEventRecord record;
    record.outbox_bucket = row.get_string("outbox_bucket");
    record.created_at = from_millis(row.get_timestamp("created_at"));
    record.event_id = row.get_string("event_id");

    auto opt_conv_id = domain::ConversationId::from_string(row.get_string("conversation_id"));
    if (opt_conv_id) {
        record.conversation_id = *opt_conv_id;
    }

    record.event_type = row.get_string("event_type");
    record.payload_json = row.get_string("payload_json");

    if (!row.is_null("published_at")) {
        record.published_at = from_millis(row.get_timestamp("published_at"));
    }

    auto opt_status = outbox_publish_status_from_string(row.get_string("publish_status"));
    record.publish_status = opt_status.value_or(OutboxPublishStatus::Pending);

    return record;
}

} // namespace

ScyllaOutboxRepository::ScyllaOutboxRepository(std::shared_ptr<db::IScyllaSession> session)
    : session_(std::move(session)) {
    if (!session_) {
        throw std::invalid_argument("ScyllaOutboxRepository requires non-null IScyllaSession");
    }
    init_prepared_statements();
}

void ScyllaOutboxRepository::init_prepared_statements() {
    prep_enqueue_event_ = session_->prepare(
        "outbox_repo_enqueue",
        "INSERT INTO securecloud_messaging.messaging_outbox_events "
        "(outbox_bucket, created_at, event_id, conversation_id, event_type, payload_json, published_at, "
        "publish_status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?);");

    prep_fetch_events_ = session_->prepare(
        "outbox_repo_fetch",
        "SELECT outbox_bucket, created_at, event_id, conversation_id, event_type, payload_json, published_at, "
        "publish_status "
        "FROM securecloud_messaging.messaging_outbox_events "
        "WHERE outbox_bucket = ? "
        "ORDER BY created_at ASC, event_id ASC LIMIT ?;");

    prep_mark_published_ =
        session_->prepare("outbox_repo_mark_published", "UPDATE securecloud_messaging.messaging_outbox_events "
                                                        "SET publish_status = ?, published_at = ? "
                                                        "WHERE outbox_bucket = ? AND created_at = ? AND event_id = ?;");
}

void ScyllaOutboxRepository::enqueue_event(const domain::ConversationOutboxEvent& event,
                                           const std::string& outbox_bucket) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string bucket = outbox_bucket.empty() ? outbox_bucket_from_time_point(event.created_at) : outbox_bucket;

    db::ScyllaParams params;
    params.add_string(bucket);
    params.add_timestamp(to_millis(event.created_at));
    params.add_string(event.event_id);
    params.add_string(event.conversation_id.to_string());
    params.add_string(domain::to_string(event.event_type));
    params.add_string(event.payload_json);
    params.add_null(); // published_at is null initially
    params.add_string(to_string(OutboxPublishStatus::Pending));

    session_->execute_prepared(prep_enqueue_event_, params);
}

std::vector<OutboxEventRecord> ScyllaOutboxRepository::fetch_pending_events(const std::string& outbox_bucket,
                                                                            size_t limit) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(outbox_bucket);
    params.add_int(static_cast<int32_t>(limit));

    auto result = session_->execute_prepared(prep_fetch_events_, params);

    std::vector<OutboxEventRecord> pending;
    for (const auto& row : result) {
        auto record = row_to_outbox_record(row);
        if (record.publish_status == OutboxPublishStatus::Pending) {
            pending.push_back(std::move(record));
            if (pending.size() >= limit) {
                break;
            }
        }
    }
    return pending;
}

void ScyllaOutboxRepository::mark_event_published(const std::string& outbox_bucket,
                                                  std::chrono::system_clock::time_point created_at,
                                                  const std::string& event_id,
                                                  std::chrono::system_clock::time_point published_at) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(to_string(OutboxPublishStatus::Published));
    params.add_timestamp(to_millis(published_at));
    params.add_string(outbox_bucket);
    params.add_timestamp(to_millis(created_at));
    params.add_string(event_id);

    session_->execute_prepared(prep_mark_published_, params);
}

} // namespace securecloud::messaging::repository
