#include "delivery/outbox_delivery_consumer.hpp"

#include "domain/message_bucket.hpp"

#include <nlohmann/json.hpp>
#include <utility>

namespace securecloud::messaging::delivery {

OutboxDeliveryConsumer::OutboxDeliveryConsumer(std::shared_ptr<repository::IOutboxRepository> outbox_repo,
                                               std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo,
                                               std::shared_ptr<IDeviceConnectionRegistry> connection_registry,
                                               std::shared_ptr<BoundedDeliveryScheduler> scheduler)
    : outbox_repo_(std::move(outbox_repo)), delivery_repo_(std::move(delivery_repo)),
      connection_registry_(std::move(connection_registry)), scheduler_(std::move(scheduler)) {}

size_t OutboxDeliveryConsumer::poll_and_dispatch(const std::string& outbox_bucket, size_t limit) {
    if (!outbox_repo_ || !delivery_repo_ || !scheduler_) {
        return 0;
    }

    const auto events = outbox_repo_->fetch_pending_events(outbox_bucket, limit);
    size_t processed_count = 0;

    for (const auto& event : events) {
        if (event.event_type != "MessageSent") {
            continue;
        }

        try {
            const auto j = nlohmann::json::parse(event.payload_json, nullptr, false);
            if (j.is_discarded() || !j.contains("message_id")) {
                // Malformed payload: mark published to avoid poison pill loops
                outbox_repo_->mark_event_published(event.outbox_bucket, event.created_at, event.event_id,
                                                   std::chrono::system_clock::now());
                continue;
            }

            const auto message_id_opt = domain::MessageId::from_string(j["message_id"].get<std::string>());
            if (!message_id_opt.has_value()) {
                outbox_repo_->mark_event_published(event.outbox_bucket, event.created_at, event.event_id,
                                                   std::chrono::system_clock::now());
                continue;
            }
            const auto& message_id = *message_id_opt;
            const auto delivery_bucket = domain::MessageBucket::from_time_point(event.created_at).value();

            // 1. Fetch recipient delivery states for this message
            const auto recipient_states = delivery_repo_->get_delivery_states_for_message(message_id);

            for (const auto& r_state : recipient_states) {
                // 2. Only dispatch if recipient device is currently connected
                if (connection_registry_ && !connection_registry_->is_online(r_state.recipient_device_id)) {
                    continue; // Offline, safely deferred to durable recovery engine (T06)
                }

                // 3. Fetch device's pending delivery record containing the encrypted envelope
                const auto pending_records =
                    delivery_repo_->fetch_pending_for_device(r_state.recipient_device_id, delivery_bucket, 100);

                for (const auto& record : pending_records) {
                    if (record.message_id != message_id) {
                        continue;
                    }

                    domain::DeliveryTask task;
                    task.message_id = record.message_id;
                    task.conversation_id = record.conversation_id;
                    task.recipient_device_id = record.device_id;
                    task.recipient_user_id = r_state.recipient_user_id;
                    task.priority = record.message_priority;
                    task.attempt_count = record.attempt_count;
                    task.accepted_at = record.accepted_at;
                    task.scheduled_at = record.accepted_at;

                    task.envelope.recipient_device_id = record.device_id;
                    task.envelope.recipient_user_id = r_state.recipient_user_id;
                    task.envelope.ciphertext_blob = record.ciphertext_blob;
                    task.envelope.ephemeral_public_key = record.ephemeral_public_key;
                    task.envelope.iv = record.iv;
                    task.envelope.auth_tag = record.auth_tag;
                    task.envelope.algorithm = record.algorithm;
                    task.envelope.protocol_version = record.protocol_version;
                    task.envelope.one_time_prekey_id = record.one_time_prekey_id;

                    // 4. Enqueue into scheduler with drop-to-durable backpressure
                    const auto status = scheduler_->schedule(std::move(task));
                    (void)status;
                    break;
                }
            }

            // 5. Mark outbox event as published
            outbox_repo_->mark_event_published(event.outbox_bucket, event.created_at, event.event_id,
                                               std::chrono::system_clock::now());
            processed_count++;
        } catch (...) {
            // Guard against runtime exceptions in consumer loop
        }
    }

    return processed_count;
}

} // namespace securecloud::messaging::delivery
