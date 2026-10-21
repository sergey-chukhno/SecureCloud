#include "service/delivery_service.hpp"

#include "domain/message_bucket.hpp"

#include <chrono>
#include <nlohmann/json.hpp>
#include <sstream>
#include <utility>

namespace securecloud::messaging::service {

DeliveryService::DeliveryService(std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo,
                                 std::shared_ptr<repository::IOutboxRepository> outbox_repo)
    : delivery_repo_(std::move(delivery_repo)), outbox_repo_(std::move(outbox_repo)) {}

ServiceResult<DeliveryAckResponse> DeliveryService::acknowledge_delivery(const DeliveryAckCommand& cmd) {
    if (!delivery_repo_) {
        return ServiceResult<DeliveryAckResponse>::fail(v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
                                                        "Delivery repository is not configured");
    }

    if (cmd.recipient_device_id.empty()) {
        return ServiceResult<DeliveryAckResponse>::fail(v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
                                                        "Recipient device ID must not be empty");
    }

    const auto now = std::chrono::system_clock::now();
    const auto effective_delivered_at = (cmd.delivered_at.time_since_epoch().count() > 0) ? cmd.delivered_at : now;

    // 1. Fetch fan-out delivery states for the message from ScyllaDB
    const auto states = delivery_repo_->get_delivery_states_for_message(cmd.message_id);
    std::optional<domain::RecipientDeliveryState> target_state;
    for (const auto& s : states) {
        if (s.recipient_device_id == cmd.recipient_device_id) {
            target_state = s;
            break;
        }
    }

    // 2. Validate target device exists for this message
    if (!target_state.has_value()) {
        return ServiceResult<DeliveryAckResponse>::fail(v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
                                                        "Message was not dispatched to the specified recipient device");
    }

    // 3. Authorize caller ownership of recipient device
    if (target_state->recipient_user_id != cmd.caller_user_id) {
        return ServiceResult<DeliveryAckResponse>::fail(
            v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
            "Caller is not authorized to acknowledge delivery for this device");
    }

    // 4. Idempotency Check: if already DELIVERED or READ, return success deterministically
    if (target_state->delivery_state == domain::DeliveryState::Delivered ||
        target_state->delivery_state == domain::DeliveryState::Read) {
        DeliveryAckResponse resp;
        resp.message_id = cmd.message_id;
        resp.state = (target_state->delivery_state == domain::DeliveryState::Read) ? v1::DELIVERY_STATE_READ
                                                                                   : v1::DELIVERY_STATE_DELIVERED;
        resp.recorded_at = target_state->delivered_at.value_or(effective_delivered_at);
        resp.is_idempotent_replay = true;
        return ServiceResult<DeliveryAckResponse>::ok(resp);
    }

    // 5. Precondition: Expired deliveries cannot transition to DELIVERED
    if (target_state->delivery_state == domain::DeliveryState::Expired) {
        return ServiceResult<DeliveryAckResponse>::fail(
            v1::MESSAGING_ERROR_CODE_MESSAGE_EXPIRED, "Message delivery window has expired and cannot be acknowledged");
    }

    // 6. Authoritatively commit delivery acknowledgement in ScyllaDB (delivery_state_by_message)
    delivery_repo_->record_delivery_ack(cmd.message_id, cmd.recipient_device_id, effective_delivered_at);

    // 7. Update active pending queue if still present in pending_deliveries_by_device
    domain::ConversationId resolved_conv_id = cmd.conversation_id.value_or(domain::ConversationId{});
    const std::string bucket = domain::MessageBucket::from_time_point(effective_delivered_at).value();
    auto pending_records = delivery_repo_->fetch_pending_for_device(cmd.recipient_device_id, bucket, 100);
    for (const auto& rec : pending_records) {
        if (rec.message_id == cmd.message_id) {
            delivery_repo_->update_device_delivery_status(cmd.recipient_device_id, rec.delivery_bucket, rec.accepted_at,
                                                          cmd.message_id, domain::DeliveryState::Delivered,
                                                          rec.attempt_count, std::nullopt);
            if (resolved_conv_id == domain::ConversationId{}) {
                resolved_conv_id = rec.conversation_id;
            }
            break;
        }
    }

    // 8. Dual-Write Safe Outbox Event Publication (ADR-005)
    if (outbox_repo_) {
        domain::ConversationOutboxEvent ack_event;
        ack_event.event_id = domain::MessageId::generate_v7().to_string();
        ack_event.conversation_id = resolved_conv_id;
        ack_event.event_type = domain::ConversationOutboxEventType::MessageDelivered;
        ack_event.created_at = effective_delivered_at;

        const auto delivered_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(effective_delivered_at.time_since_epoch()).count();
        nlohmann::json payload;
        payload["message_id"] = cmd.message_id.to_string();
        payload["recipient_device_id"] = cmd.recipient_device_id.str();
        payload["recipient_user_id"] = target_state->recipient_user_id.str();
        payload["delivered_at_unix_ms"] = delivered_ms;
        ack_event.payload_json = payload.dump();

        outbox_repo_->enqueue_event(ack_event);
    }

    DeliveryAckResponse resp;
    resp.message_id = cmd.message_id;
    resp.state = v1::DELIVERY_STATE_DELIVERED;
    resp.recorded_at = effective_delivered_at;
    resp.is_idempotent_replay = false;
    return ServiceResult<DeliveryAckResponse>::ok(resp);
}

} // namespace securecloud::messaging::service
