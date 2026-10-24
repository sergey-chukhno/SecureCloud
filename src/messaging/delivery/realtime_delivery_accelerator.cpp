#include "delivery/realtime_delivery_accelerator.hpp"

#include "domain/message_bucket.hpp"
#include "telemetry/presence_metrics.hpp"

#include <utility>

namespace securecloud::messaging::delivery {

RealtimeDeliveryAccelerator::RealtimeDeliveryAccelerator(
    std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo,
    std::shared_ptr<BoundedDeliveryScheduler> scheduler, std::shared_ptr<IDeviceConnectionRegistry> connection_registry,
    Config config)
    : delivery_repo_(std::move(delivery_repo)), scheduler_(std::move(scheduler)),
      connection_registry_(std::move(connection_registry)), config_(config) {}

size_t RealtimeDeliveryAccelerator::on_device_connected(const domain::DeviceId& device_id,
                                                        const domain::UserId& user_id,
                                                        const std::string& delivery_bucket) {
    if (!delivery_repo_ || !scheduler_) {
        return 0;
    }

    // Verify recipient device is currently online if connection registry is configured
    if (connection_registry_ && !connection_registry_->is_online(device_id)) {
        return 0;
    }

    const auto now = std::chrono::system_clock::now();
    std::string bucket = delivery_bucket;
    if (bucket.empty()) {
        bucket = domain::MessageBucket::from_time_point(now).value();
    }

    const auto records = delivery_repo_->fetch_pending_for_device(device_id, bucket, config_.max_fast_track_batch);

    size_t enqueued_count = 0;
    for (const auto& rec : records) {
        if (rec.delivery_state != domain::DeliveryState::Queued &&
            rec.delivery_state != domain::DeliveryState::Delivering) {
            continue;
        }

        // Check if exceeded maximum delivery TTL
        if (now - rec.accepted_at > config_.max_delivery_ttl) {
            delivery_repo_->update_device_delivery_status(device_id, bucket, rec.accepted_at, rec.message_id,
                                                          domain::DeliveryState::Expired, rec.attempt_count,
                                                          std::nullopt);
            continue;
        }

        domain::DeliveryTask task;
        task.message_id = rec.message_id;
        task.conversation_id = rec.conversation_id;
        task.recipient_device_id = rec.device_id;
        task.priority = rec.message_priority;
        task.attempt_count = rec.attempt_count;
        task.accepted_at = rec.accepted_at;
        task.scheduled_at = now;

        // Populate Zero-Plaintext Encrypted Envelope
        task.envelope.ciphertext_blob = rec.ciphertext_blob;
        task.envelope.ephemeral_public_key = rec.ephemeral_public_key;
        task.envelope.iv = rec.iv;
        task.envelope.auth_tag = rec.auth_tag;
        task.envelope.algorithm = rec.algorithm;
        task.envelope.protocol_version = rec.protocol_version;
        task.envelope.one_time_prekey_id = rec.one_time_prekey_id;

        // Resolve recipient user ID
        if (!user_id.empty()) {
            task.recipient_user_id = user_id;
        } else {
            const auto states = delivery_repo_->get_delivery_states_for_message(rec.message_id);
            for (const auto& s : states) {
                if (s.recipient_device_id == rec.device_id) {
                    task.recipient_user_id = s.recipient_user_id;
                    break;
                }
            }
        }

        const auto status = scheduler_->schedule(std::move(task));
        if (status == SchedulerStatus::Enqueued) {
            ++enqueued_count;
        } else {
            // Drop-to-durable backpressure: in-memory queue saturated, stop scheduling for this burst
            break;
        }
    }

    total_accelerated_.fetch_add(enqueued_count, std::memory_order_relaxed);
    if (enqueued_count > 0) {
        telemetry::PresenceMetrics::instance().increment_fast_track_dispatches(enqueued_count);
    }
    return enqueued_count;
}

void RealtimeDeliveryAccelerator::attach_to_lifecycle_manager(ConnectionLifecycleManager& lifecycle_manager) {
    lifecycle_manager.register_connected_callback(
        [this](const domain::DeviceId& dev_id, const domain::UserId& uid) { on_device_connected(dev_id, uid); });
}

size_t RealtimeDeliveryAccelerator::total_accelerated_count() const noexcept {
    return total_accelerated_.load(std::memory_order_relaxed);
}

} // namespace securecloud::messaging::delivery
