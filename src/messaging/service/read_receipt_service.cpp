#include "service/read_receipt_service.hpp"

#include "audit/canonical_audit_mapper.hpp"
#include "domain/audit_event.hpp"
#include "domain/audit_event_id.hpp"

#include <chrono>
#include <map>
#include <nlohmann/json.hpp>
#include <utility>

namespace securecloud::messaging::service {

ReadReceiptService::ReadReceiptService(std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo,
                                       std::shared_ptr<repository::IMembershipRepository> membership_repo,
                                       std::shared_ptr<repository::IOutboxRepository> outbox_repo,
                                       std::shared_ptr<repository::IMessagingAuditOutboxRepository> audit_repo,
                                       DeviceStatusChecker device_status_checker)
    : delivery_repo_(std::move(delivery_repo)), membership_repo_(std::move(membership_repo)),
      outbox_repo_(std::move(outbox_repo)), audit_repo_(std::move(audit_repo)),
      device_status_checker_(std::move(device_status_checker)) {}

ServiceResult<ReadReceiptResponse> ReadReceiptService::record_read_receipt(const ReadReceiptCommand& cmd) {
    if (!delivery_repo_) {
        return ServiceResult<ReadReceiptResponse>::fail(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                                        "Delivery repository is not configured");
    }

    if (cmd.message_id == domain::MessageId{}) {
        return ServiceResult<ReadReceiptResponse>::fail(v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
                                                        "Message ID must not be empty");
    }

    if (cmd.reader_device_id.empty()) {
        return ServiceResult<ReadReceiptResponse>::fail(v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
                                                        "Reader device ID must not be empty");
    }

    if (cmd.caller_user_id.empty()) {
        return ServiceResult<ReadReceiptResponse>::fail(v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
                                                        "Caller user ID must not be empty");
    }

    if (!cmd.caller_device_id.empty() && cmd.caller_device_id != cmd.reader_device_id) {
        return ServiceResult<ReadReceiptResponse>::fail(
            v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
            "Caller device cannot submit read receipts on behalf of a different device");
    }

    if (membership_repo_ && cmd.conversation_id != domain::ConversationId{}) {
        auto participant = membership_repo_->find_participant(cmd.conversation_id, cmd.caller_user_id);
        if (!participant.has_value() || participant->status != domain::MembershipStatus::Active) {
            return ServiceResult<ReadReceiptResponse>::fail(
                v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
                "Caller is not an active participant in the specified conversation");
        }
    }

    if (device_status_checker_ && !device_status_checker_(cmd.reader_device_id)) {
        return ServiceResult<ReadReceiptResponse>::fail(
            v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED,
            "Reader device has been revoked and cannot submit valid read receipts");
    }

    const size_t stripe_idx =
        std::hash<std::string>{}(cmd.message_id.to_string() + ":" + cmd.reader_device_id.str()) % kNumStripes;
    std::lock_guard<std::mutex> stripe_lock(receipt_stripes_[stripe_idx]);

    const auto states = delivery_repo_->get_delivery_states_for_message(cmd.message_id);
    if (states.empty()) {
        return ServiceResult<ReadReceiptResponse>::fail(v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
                                                        "Message delivery states not found");
    }

    std::optional<domain::RecipientDeliveryState> target_state;
    for (const auto& s : states) {
        if (s.recipient_device_id == cmd.reader_device_id) {
            target_state = s;
            break;
        }
    }

    if (!target_state.has_value()) {
        return ServiceResult<ReadReceiptResponse>::fail(v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
                                                        "Message was not dispatched to the specified reader device");
    }

    if (target_state->recipient_user_id != cmd.caller_user_id) {
        return ServiceResult<ReadReceiptResponse>::fail(
            v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
            "Caller is not authorized to submit read receipt on behalf of another recipient");
    }

    if (target_state->delivery_state == domain::DeliveryState::Expired) {
        return ServiceResult<ReadReceiptResponse>::fail(
            v1::MESSAGING_ERROR_CODE_MESSAGE_EXPIRED,
            "Message delivery window has expired and cannot be marked as read");
    }

    const auto now = std::chrono::system_clock::now();
    const auto effective_read_at = (cmd.read_at.time_since_epoch().count() > 0) ? cmd.read_at : now;

    if (target_state->read_at.has_value()) {
        ReadReceiptResponse resp;
        resp.message_id = cmd.message_id;
        resp.conversation_id = cmd.conversation_id;
        resp.reader_user_id = cmd.caller_user_id;
        resp.reader_device_id = cmd.reader_device_id;
        resp.state = v1::DELIVERY_STATE_READ;
        resp.recorded_at = *target_state->read_at;
        resp.is_idempotent_replay = true;
        return ServiceResult<ReadReceiptResponse>::ok(resp);
    }

    delivery_repo_->record_read_ack(cmd.message_id, cmd.reader_device_id, effective_read_at);

    if (outbox_repo_) {
        domain::ConversationOutboxEvent read_event;
        read_event.event_id = domain::MessageId::generate_v7().to_string();
        read_event.conversation_id = cmd.conversation_id;
        read_event.event_type = domain::ConversationOutboxEventType::MessageRead;
        read_event.created_at = effective_read_at;

        const auto read_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(effective_read_at.time_since_epoch()).count();
        nlohmann::json payload;
        payload["message_id"] = cmd.message_id.to_string();
        payload["conversation_id"] = cmd.conversation_id.to_string();
        payload["reader_device_id"] = cmd.reader_device_id.str();
        payload["reader_user_id"] = cmd.caller_user_id.str();
        payload["read_at_unix_ms"] = read_ms;
        read_event.payload_json = payload.dump();

        outbox_repo_->enqueue_event(read_event);
    }

    if (audit_repo_) {
        const nlohmann::json audit_meta = {
            {"conversation_id", cmd.conversation_id.to_string()},
        };
        domain::MessagingAuditEvent read_audit{
            .event_id = domain::generate_message_audit_event_id(cmd.message_id, cmd.reader_device_id,
                                                                domain::MessagingAuditEventType::MessageRead),
            .event_type = domain::MessagingAuditEventType::MessageRead,
            .severity = domain::MessagingAuditSeverity::Info,
            .occurred_at = effective_read_at,
            .actor_user_id = cmd.caller_user_id,
            .actor_device_id = cmd.reader_device_id,
            .target_resource = cmd.message_id.to_string(),
            .payload_json = audit_meta.dump(),
            .correlation_id = cmd.correlation_id,
        };
        audit::stage_canonical_audit_event(audit_repo_.get(), read_audit, cmd.conversation_id.to_string());
    }

    ReadReceiptResponse resp;
    resp.message_id = cmd.message_id;
    resp.conversation_id = cmd.conversation_id;
    resp.reader_user_id = cmd.caller_user_id;
    resp.reader_device_id = cmd.reader_device_id;
    resp.state = v1::DELIVERY_STATE_READ;
    resp.recorded_at = effective_read_at;
    resp.is_idempotent_replay = false;
    return ServiceResult<ReadReceiptResponse>::ok(resp);
}

ServiceResult<MessageReadStatusResponse>
ReadReceiptService::get_message_read_status(const domain::ConversationId& conversation_id,
                                            const domain::MessageId& message_id, const domain::UserId& caller_user_id) {
    if (!delivery_repo_) {
        return ServiceResult<MessageReadStatusResponse>::fail(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                                              "Delivery repository is not configured");
    }

    if (caller_user_id.empty()) {
        return ServiceResult<MessageReadStatusResponse>::fail(v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
                                                              "Caller user ID must not be empty");
    }

    if (membership_repo_ && conversation_id != domain::ConversationId{}) {
        auto participant = membership_repo_->find_participant(conversation_id, caller_user_id);
        if (!participant.has_value() || participant->status != domain::MembershipStatus::Active) {
            return ServiceResult<MessageReadStatusResponse>::fail(
                v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
                "Caller is not an active participant in the specified conversation");
        }
    }

    const auto states = delivery_repo_->get_delivery_states_for_message(message_id);
    if (states.empty()) {
        return ServiceResult<MessageReadStatusResponse>::fail(v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
                                                              "Message delivery states not found");
    }

    std::map<domain::UserId, domain::LogicalRecipientReadStatus> user_map;
    for (const auto& s : states) {
        auto& status = user_map[s.recipient_user_id];
        status.user_id = s.recipient_user_id;

        if (s.read_at.has_value()) {
            status.read_state = domain::ReadState::Read;
            if (!status.read_at.has_value() || *s.read_at < *status.read_at) {
                status.read_at = s.read_at;
                status.reader_device_id = s.recipient_device_id;
            }
        } else if (status.read_state != domain::ReadState::Read) {
            status.read_state = domain::ReadState::Unread;
        }
    }

    MessageReadStatusResponse resp;
    resp.message_id = message_id;
    resp.conversation_id = conversation_id;
    resp.total_recipients = static_cast<uint32_t>(user_map.size());
    resp.read_recipients = 0;
    resp.recipient_read_statuses.reserve(user_map.size());

    for (auto& [_, st] : user_map) {
        if (st.read_state == domain::ReadState::Read) {
            resp.read_recipients++;
        }
        resp.recipient_read_statuses.push_back(std::move(st));
    }

    return ServiceResult<MessageReadStatusResponse>::ok(resp);
}

ServiceResult<domain::MessageDeliverySummary>
ReadReceiptService::get_message_delivery_summary(const domain::ConversationId& conversation_id,
                                                 const domain::MessageId& message_id,
                                                 const domain::UserId& caller_user_id) {
    if (!delivery_repo_) {
        return ServiceResult<domain::MessageDeliverySummary>::fail(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                                                   "Delivery repository is not configured");
    }

    if (caller_user_id.empty()) {
        return ServiceResult<domain::MessageDeliverySummary>::fail(v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
                                                                   "Caller user ID must not be empty");
    }

    if (membership_repo_ && conversation_id != domain::ConversationId{}) {
        auto participant = membership_repo_->find_participant(conversation_id, caller_user_id);
        if (!participant.has_value() || participant->status != domain::MembershipStatus::Active) {
            return ServiceResult<domain::MessageDeliverySummary>::fail(
                v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
                "Caller is not an active participant in the specified conversation");
        }
    }

    auto summary_opt = delivery_repo_->get_message_delivery_summary(message_id);
    if (!summary_opt.has_value()) {
        return ServiceResult<domain::MessageDeliverySummary>::fail(v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
                                                                   "Message delivery states not found");
    }

    summary_opt->conversation_id = conversation_id;
    return ServiceResult<domain::MessageDeliverySummary>::ok(std::move(*summary_opt));
}

} // namespace securecloud::messaging::service
