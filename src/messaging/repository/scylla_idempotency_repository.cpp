#include "messaging/repository/scylla_idempotency_repository.hpp"

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

domain::IdempotencyRecord row_to_idempotency_record(const db::ScyllaRow& row) {
    domain::IdempotencyRecord record;
    record.sender_device_id = domain::DeviceId(row.get_string("sender_device_id"));
    record.idempotency_key = row.get_string("idempotency_key");

    auto opt_msg_id = domain::MessageId::from_string(row.get_string("message_id"));
    if (opt_msg_id) {
        record.message_id = *opt_msg_id;
    }

    auto opt_conv_id = domain::ConversationId::from_string(row.get_string("conversation_id"));
    if (opt_conv_id) {
        record.conversation_id = *opt_conv_id;
    }

    record.message_sequence = static_cast<uint64_t>(row.get_int64("message_sequence"));

    auto opt_status = domain::submission_status_from_string(row.get_string("submission_status"));
    record.submission_status = opt_status.value_or(domain::SubmissionStatus::Processing);

    record.created_at = from_millis(row.get_timestamp("created_at"));

    if (row.has_column("request_fingerprint") && !row.is_null("request_fingerprint")) {
        record.request_fingerprint = row.get_string("request_fingerprint");
    }

    return record;
}

} // namespace

ScyllaIdempotencyRepository::ScyllaIdempotencyRepository(std::shared_ptr<db::IScyllaSession> session)
    : session_(std::move(session)) {
    if (!session_) {
        throw std::invalid_argument("ScyllaIdempotencyRepository requires non-null IScyllaSession");
    }
    init_prepared_statements();
}

void ScyllaIdempotencyRepository::init_prepared_statements() {
    prep_find_submission_ =
        session_->prepare("idem_repo_find_submission",
                          "SELECT sender_device_id, idempotency_key, message_id, conversation_id, message_sequence, "
                          "submission_status, created_at, request_fingerprint "
                          "FROM securecloud_messaging.message_submission_by_idempotency_key "
                          "WHERE sender_device_id = ? AND idempotency_key = ?;");

    prep_save_submission_ =
        session_->prepare("idem_repo_save_submission",
                          "INSERT INTO securecloud_messaging.message_submission_by_idempotency_key "
                          "(sender_device_id, idempotency_key, message_id, conversation_id, message_sequence, "
                          "submission_status, created_at, request_fingerprint) "
                          "VALUES (?, ?, ?, ?, ?, ?, ?, ?);");
}

std::optional<domain::IdempotencyRecord>
ScyllaIdempotencyRepository::find_submission(const domain::DeviceId& sender_device_id,
                                             const std::string& idempotency_key) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(sender_device_id.str());
    params.add_string(idempotency_key);

    auto result = session_->execute_prepared(prep_find_submission_, params);
    if (result.empty()) {
        return std::nullopt;
    }

    return row_to_idempotency_record(result.front());
}

void ScyllaIdempotencyRepository::save_submission(const domain::IdempotencyRecord& record) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(record.sender_device_id.str());
    params.add_string(record.idempotency_key);
    params.add_string(record.message_id.to_string());
    params.add_string(record.conversation_id.to_string());
    params.add_int64(static_cast<int64_t>(record.message_sequence));
    params.add_string(domain::to_string(record.submission_status));
    params.add_timestamp(to_millis(record.created_at));
    params.add_string(record.request_fingerprint);

    session_->execute_prepared(prep_save_submission_, params);
}

} // namespace securecloud::messaging::repository
