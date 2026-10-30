#include "messaging/repository/scylla_delivery_state_repository.hpp"

#include "service/delivery_state_transition_guard.hpp"

#include <chrono>
#include <map>
#include <stdexcept>

namespace securecloud::messaging::repository {
namespace {

inline int64_t to_millis(std::chrono::system_clock::time_point tp) noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
}

inline std::chrono::system_clock::time_point from_millis(int64_t ms) noexcept {
    return std::chrono::system_clock::time_point(std::chrono::milliseconds(ms));
}

domain::DeviceDeliveryRecord row_to_delivery_record(const db::ScyllaRow& row) {
    domain::DeviceDeliveryRecord record;
    record.device_id = domain::DeviceId(row.get_string("device_id"));
    record.delivery_bucket = row.get_string("delivery_bucket");
    record.accepted_at = from_millis(row.get_timestamp("accepted_at"));

    auto opt_msg_id = domain::MessageId::from_string(row.get_string("message_id"));
    if (opt_msg_id) {
        record.message_id = *opt_msg_id;
    }

    auto opt_conv_id = domain::ConversationId::from_string(row.get_string("conversation_id"));
    if (opt_conv_id) {
        record.conversation_id = *opt_conv_id;
    }

    record.message_sequence = static_cast<uint64_t>(row.get_int64("message_sequence"));

    auto opt_priority = domain::message_priority_from_string(row.get_string("message_priority"));
    record.message_priority = opt_priority.value_or(domain::MessagePriority::Normal);

    auto opt_state = domain::delivery_state_from_string(row.get_string("delivery_state"));
    record.delivery_state = opt_state.value_or(domain::DeliveryState::Pending);

    record.attempt_count = row.get_int("attempt_count");

    if (!row.is_null("next_retry_at")) {
        record.next_retry_at = from_millis(row.get_timestamp("next_retry_at"));
    }

    if (row.has_column("ciphertext_blob") && !row.is_null("ciphertext_blob")) {
        const auto& blob = row.get_blob("ciphertext_blob");
        record.ciphertext_blob.assign(reinterpret_cast<const char*>(blob.data()), blob.size());
    }
    if (row.has_column("ephemeral_public_key") && !row.is_null("ephemeral_public_key")) {
        record.ephemeral_public_key = row.get_blob("ephemeral_public_key");
    }
    if (row.has_column("iv") && !row.is_null("iv")) {
        record.iv = row.get_blob("iv");
    }
    if (row.has_column("auth_tag") && !row.is_null("auth_tag")) {
        record.auth_tag = row.get_blob("auth_tag");
    }
    if (row.has_column("algorithm") && !row.is_null("algorithm")) {
        auto algo_opt = domain::e2e_algorithm_from_string(row.get_string("algorithm"));
        if (algo_opt) {
            record.algorithm = *algo_opt;
        }
    }
    if (row.has_column("protocol_version") && !row.is_null("protocol_version")) {
        auto proto_opt = domain::e2e_protocol_version_from_int(row.get_int("protocol_version"));
        if (proto_opt) {
            record.protocol_version = *proto_opt;
        }
    }
    if (row.has_column("one_time_prekey_id") && !row.is_null("one_time_prekey_id")) {
        record.one_time_prekey_id = row.get_string("one_time_prekey_id");
    }

    return record;
}

domain::RecipientDeliveryState row_to_recipient_state(const db::ScyllaRow& row) {
    domain::RecipientDeliveryState state;

    auto opt_msg_id = domain::MessageId::from_string(row.get_string("message_id"));
    if (opt_msg_id) {
        state.message_id = *opt_msg_id;
    }

    state.recipient_device_id = domain::DeviceId(row.get_string("recipient_device_id"));
    state.recipient_user_id = domain::UserId(row.get_string("recipient_user_id"));

    auto opt_state = domain::delivery_state_from_string(row.get_string("delivery_state"));
    state.delivery_state = opt_state.value_or(domain::DeliveryState::Pending);

    if (!row.is_null("delivered_at")) {
        state.delivered_at = from_millis(row.get_timestamp("delivered_at"));
    }
    if (!row.is_null("read_at")) {
        state.read_at = from_millis(row.get_timestamp("read_at"));
    }

    return state;
}

} // namespace

ScyllaDeliveryStateRepository::ScyllaDeliveryStateRepository(std::shared_ptr<db::IScyllaSession> session)
    : session_(std::move(session)) {
    if (!session_) {
        throw std::invalid_argument("ScyllaDeliveryStateRepository requires non-null IScyllaSession");
    }
    init_prepared_statements();
}

void ScyllaDeliveryStateRepository::init_prepared_statements() {
    prep_insert_pending_ = session_->prepare(
        "deliv_repo_insert_pending",
        "INSERT INTO securecloud_messaging.pending_deliveries_by_device "
        "(device_id, delivery_bucket, accepted_at, message_id, conversation_id, message_sequence, "
        "message_priority, delivery_state, attempt_count, next_retry_at, "
        "ciphertext_blob, ephemeral_public_key, iv, auth_tag, algorithm, protocol_version, one_time_prekey_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");

    prep_fetch_pending_ = session_->prepare(
        "deliv_repo_fetch_pending",
        "SELECT device_id, delivery_bucket, accepted_at, message_id, conversation_id, message_sequence, "
        "message_priority, delivery_state, attempt_count, next_retry_at, "
        "ciphertext_blob, ephemeral_public_key, iv, auth_tag, algorithm, protocol_version, one_time_prekey_id "
        "FROM securecloud_messaging.pending_deliveries_by_device "
        "WHERE device_id = ? AND delivery_bucket = ? "
        "ORDER BY accepted_at ASC, message_id ASC LIMIT ?;");

    prep_update_pending_ =
        session_->prepare("deliv_repo_update_pending",
                          "UPDATE securecloud_messaging.pending_deliveries_by_device "
                          "SET delivery_state = ?, attempt_count = ?, next_retry_at = ? "
                          "WHERE device_id = ? AND delivery_bucket = ? AND accepted_at = ? AND message_id = ?;");

    prep_insert_recipient_state_ =
        session_->prepare("deliv_repo_insert_recip_state",
                          "INSERT INTO securecloud_messaging.delivery_state_by_message "
                          "(message_id, recipient_device_id, recipient_user_id, delivery_state, delivered_at, read_at) "
                          "VALUES (?, ?, ?, ?, ?, ?);");

    prep_delivery_ack_ =
        session_->prepare("deliv_repo_delivery_ack", "UPDATE securecloud_messaging.delivery_state_by_message "
                                                     "SET delivery_state = 'DELIVERED', delivered_at = ? "
                                                     "WHERE message_id = ? AND recipient_device_id = ?;");

    prep_read_ack_ = session_->prepare("deliv_repo_read_ack", "UPDATE securecloud_messaging.delivery_state_by_message "
                                                              "SET delivery_state = 'READ', read_at = ? "
                                                              "WHERE message_id = ? AND recipient_device_id = ?;");

    prep_get_message_states_ = session_->prepare(
        "deliv_repo_get_msg_states",
        "SELECT message_id, recipient_device_id, recipient_user_id, delivery_state, delivered_at, read_at "
        "FROM securecloud_messaging.delivery_state_by_message "
        "WHERE message_id = ?;");

    prep_update_delivery_state_ =
        session_->prepare("deliv_repo_update_state", "UPDATE securecloud_messaging.delivery_state_by_message "
                                                     "SET delivery_state = ?, delivered_at = ? "
                                                     "WHERE message_id = ? AND recipient_device_id = ?;");

    prep_get_single_device_state_ = session_->prepare(
        "deliv_repo_get_single_state",
        "SELECT message_id, recipient_device_id, recipient_user_id, delivery_state, delivered_at, read_at "
        "FROM securecloud_messaging.delivery_state_by_message "
        "WHERE message_id = ? AND recipient_device_id = ?;");

    prep_get_device_record_ = session_->prepare(
        "deliv_repo_get_device_record",
        "SELECT device_id, delivery_bucket, accepted_at, message_id, conversation_id, message_sequence, "
        "message_priority, delivery_state, attempt_count, next_retry_at, "
        "ciphertext_blob, ephemeral_public_key, iv, auth_tag, algorithm, protocol_version, one_time_prekey_id "
        "FROM securecloud_messaging.pending_deliveries_by_device "
        "WHERE device_id = ? AND message_id = ?;");
}

void ScyllaDeliveryStateRepository::save_pending_deliveries(const std::vector<domain::DeviceDeliveryRecord>& records) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& record : records) {
        db::ScyllaParams params;
        params.add_string(record.device_id.str());
        params.add_string(record.delivery_bucket);
        params.add_timestamp(to_millis(record.accepted_at));
        params.add_string(record.message_id.to_string());
        params.add_string(record.conversation_id.to_string());
        params.add_int64(static_cast<int64_t>(record.message_sequence));
        params.add_string(domain::to_string(record.message_priority));
        params.add_string(domain::to_string(record.delivery_state));
        params.add_int(record.attempt_count);
        if (record.next_retry_at) {
            params.add_timestamp(to_millis(*record.next_retry_at));
        } else {
            params.add_null();
        }

        // E2E Envelope Fields (MSG-006)
        if (!record.ciphertext_blob.empty()) {
            params.add_blob(std::vector<uint8_t>(record.ciphertext_blob.begin(), record.ciphertext_blob.end()));
        } else {
            params.add_null();
        }

        if (!record.ephemeral_public_key.empty()) {
            params.add_blob(record.ephemeral_public_key);
        } else {
            params.add_null();
        }

        if (!record.iv.empty()) {
            params.add_blob(record.iv);
        } else {
            params.add_null();
        }

        if (!record.auth_tag.empty()) {
            params.add_blob(record.auth_tag);
        } else {
            params.add_null();
        }

        params.add_string(domain::to_string(record.algorithm));
        params.add_int(static_cast<int32_t>(record.protocol_version));

        if (record.one_time_prekey_id.has_value()) {
            params.add_string(*record.one_time_prekey_id);
        } else {
            params.add_null();
        }

        session_->execute_prepared(prep_insert_pending_, params);
    }
}

std::vector<domain::DeviceDeliveryRecord>
ScyllaDeliveryStateRepository::fetch_pending_for_device(const domain::DeviceId& device_id,
                                                        const std::string& delivery_bucket, size_t limit) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(device_id.str());
    params.add_string(delivery_bucket);
    params.add_int(static_cast<int32_t>(limit));

    auto result = session_->execute_prepared(prep_fetch_pending_, params);

    std::vector<domain::DeviceDeliveryRecord> records;
    records.reserve(result.size());
    for (const auto& row : result) {
        records.push_back(row_to_delivery_record(row));
    }
    return records;
}

void ScyllaDeliveryStateRepository::update_device_delivery_status(
    const domain::DeviceId& device_id, const std::string& delivery_bucket,
    const std::chrono::system_clock::time_point& accepted_at, const domain::MessageId& message_id,
    domain::DeliveryState state, int32_t attempt_count,
    std::optional<std::chrono::system_clock::time_point> next_retry) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(domain::to_string(state));
    params.add_int(attempt_count);
    if (next_retry) {
        params.add_timestamp(to_millis(*next_retry));
    } else {
        params.add_null();
    }
    params.add_string(device_id.str());
    params.add_string(delivery_bucket);
    params.add_timestamp(to_millis(accepted_at));
    params.add_string(message_id.to_string());

    session_->execute_prepared(prep_update_pending_, params);
}

void ScyllaDeliveryStateRepository::save_recipient_delivery_states(
    const std::vector<domain::RecipientDeliveryState>& states) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& state : states) {
        db::ScyllaParams params;
        params.add_string(state.message_id.to_string());
        params.add_string(state.recipient_device_id.str());
        params.add_string(state.recipient_user_id.str());
        params.add_string(domain::to_string(state.delivery_state));
        if (state.delivered_at) {
            params.add_timestamp(to_millis(*state.delivered_at));
        } else {
            params.add_null();
        }
        if (state.read_at) {
            params.add_timestamp(to_millis(*state.read_at));
        } else {
            params.add_null();
        }

        session_->execute_prepared(prep_insert_recipient_state_, params);
    }
}

void ScyllaDeliveryStateRepository::record_delivery_ack(const domain::MessageId& message_id,
                                                        const domain::DeviceId& recipient_device_id,
                                                        const std::chrono::system_clock::time_point& delivered_at) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_timestamp(to_millis(delivered_at));
    params.add_string(message_id.to_string());
    params.add_string(recipient_device_id.str());

    session_->execute_prepared(prep_delivery_ack_, params);
}

void ScyllaDeliveryStateRepository::record_read_ack(const domain::MessageId& message_id,
                                                    const domain::DeviceId& recipient_device_id,
                                                    const std::chrono::system_clock::time_point& read_at) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_timestamp(to_millis(read_at));
    params.add_string(message_id.to_string());
    params.add_string(recipient_device_id.str());

    session_->execute_prepared(prep_read_ack_, params);
}

std::vector<domain::RecipientDeliveryState>
ScyllaDeliveryStateRepository::get_delivery_states_for_message(const domain::MessageId& message_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(message_id.to_string());

    auto result = session_->execute_prepared(prep_get_message_states_, params);

    std::vector<domain::RecipientDeliveryState> states;
    states.reserve(result.size());
    for (const auto& row : result) {
        states.push_back(row_to_recipient_state(row));
    }
    return states;
}

bool ScyllaDeliveryStateRepository::update_delivery_state_monotonic(
    const domain::MessageId& message_id, const domain::DeviceId& recipient_device_id, domain::DeliveryState new_state,
    const std::chrono::system_clock::time_point& updated_at) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams fetch_params;
    fetch_params.add_string(message_id.to_string());
    fetch_params.add_string(recipient_device_id.str());

    auto rows = session_->execute_prepared(prep_get_single_device_state_, fetch_params);
    if (rows.empty()) {
        return false;
    }

    const auto& row = rows.front();
    auto current_state_opt = domain::delivery_state_from_string(row.get_string("delivery_state"));
    auto current_state = current_state_opt.value_or(domain::DeliveryState::Pending);

    // Idempotency: re-applying current state is a no-op that succeeds
    if (service::DeliveryStateTransitionGuard::is_idempotent(current_state, new_state)) {
        return true;
    }

    // Monotonicity / Regression check
    if (service::DeliveryStateTransitionGuard::is_regression(current_state, new_state) ||
        !service::DeliveryStateTransitionGuard::can_transition(current_state, new_state)) {
        return false;
    }

    // Valid transition: commit update
    db::ScyllaParams update_params;
    update_params.add_string(domain::to_string(new_state));

    if (new_state == domain::DeliveryState::Delivered) {
        if (row.is_null("delivered_at")) {
            update_params.add_timestamp(to_millis(updated_at));
        } else {
            update_params.add_timestamp(row.get_timestamp("delivered_at"));
        }
    } else {
        if (!row.is_null("delivered_at")) {
            update_params.add_timestamp(row.get_timestamp("delivered_at"));
        } else {
            update_params.add_null();
        }
    }

    update_params.add_string(message_id.to_string());
    update_params.add_string(recipient_device_id.str());

    session_->execute_prepared(prep_update_delivery_state_, update_params);
    return true;
}

std::optional<domain::MessageDeliverySummary>
ScyllaDeliveryStateRepository::get_message_delivery_summary(const domain::MessageId& message_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(message_id.to_string());

    auto rows = session_->execute_prepared(prep_get_message_states_, params);
    if (rows.empty()) {
        return std::nullopt;
    }

    domain::MessageDeliverySummary summary;
    summary.message_id = message_id;

    std::map<domain::UserId, domain::LogicalRecipientReadStatus> read_status_map;

    for (const auto& row : rows) {
        domain::DeviceDeliveryStatus dev_status;
        dev_status.device_id = domain::DeviceId(row.get_string("recipient_device_id"));
        dev_status.recipient_user_id = domain::UserId(row.get_string("recipient_user_id"));

        auto opt_state = domain::delivery_state_from_string(row.get_string("delivery_state"));
        dev_status.delivery_state = opt_state.value_or(domain::DeliveryState::Pending);

        if (!row.is_null("delivered_at")) {
            dev_status.delivered_at = from_millis(row.get_timestamp("delivered_at"));
        }

        summary.total_targets++;
        if (dev_status.delivery_state == domain::DeliveryState::Delivered) {
            summary.delivered_targets++;
        } else if (dev_status.delivery_state == domain::DeliveryState::Expired) {
            summary.expired_targets++;
        } else {
            summary.pending_targets++;
        }

        // Track per-user logical read status
        auto& user_status = read_status_map[dev_status.recipient_user_id];
        user_status.user_id = dev_status.recipient_user_id;
        if (!row.is_null("read_at")) {
            auto row_read_at = from_millis(row.get_timestamp("read_at"));
            if (user_status.read_state != domain::ReadState::Read || !user_status.read_at ||
                row_read_at < *user_status.read_at) {
                user_status.read_state = domain::ReadState::Read;
                user_status.read_at = row_read_at;
                user_status.reader_device_id = dev_status.device_id;
            }
        }

        summary.device_statuses.push_back(std::move(dev_status));
    }

    summary.recipient_read_statuses.reserve(read_status_map.size());
    for (auto& [_, status] : read_status_map) {
        summary.recipient_read_statuses.push_back(std::move(status));
    }

    return summary;
}

std::optional<domain::DeviceDeliveryRecord>
ScyllaDeliveryStateRepository::get_delivery_record_for_device(const domain::DeviceId& device_id,
                                                              const domain::MessageId& message_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    db::ScyllaParams params;
    params.add_string(device_id.str());
    params.add_string(message_id.to_string());

    auto result = session_->execute_prepared(prep_get_device_record_, params);
    if (result.empty()) {
        return std::nullopt;
    }
    return row_to_delivery_record(result.front());
}

} // namespace securecloud::messaging::repository
