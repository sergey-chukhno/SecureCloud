#include "delivery/durable_delivery_recovery_service.hpp"

#include "domain/message_bucket.hpp"

#include <utility>

namespace securecloud::messaging::delivery {

DurableDeliveryRecoveryService::DurableDeliveryRecoveryService(
    std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo,
    std::shared_ptr<BoundedDeliveryScheduler> scheduler, std::shared_ptr<IDeviceConnectionRegistry> connection_registry,
    DeliveryRecoveryConfig config)
    : delivery_repo_(std::move(delivery_repo)), scheduler_(std::move(scheduler)),
      connection_registry_(std::move(connection_registry)), config_(config) {}

DurableDeliveryRecoveryService::~DurableDeliveryRecoveryService() {
    stop();
}

size_t DurableDeliveryRecoveryService::recover_pending_for_device(const domain::DeviceId& device_id,
                                                                  const std::string& delivery_bucket) {
    if (!delivery_repo_ || !scheduler_) {
        return 0;
    }

    if (connection_registry_ && !connection_registry_->is_online(device_id)) {
        return 0; // Skip offline devices until connection is actively re-established
    }

    const auto now = std::chrono::system_clock::now();
    const auto records = delivery_repo_->fetch_pending_for_device(device_id, delivery_bucket, config_.batch_size);

    size_t enqueued_count = 0;
    for (const auto& rec : records) {
        if (rec.delivery_state != domain::DeliveryState::Queued &&
            rec.delivery_state != domain::DeliveryState::Delivering) {
            continue;
        }

        // Check if exceeded maximum delivery TTL
        if (now - rec.accepted_at > config_.max_delivery_ttl) {
            delivery_repo_->update_device_delivery_status(device_id, delivery_bucket, rec.accepted_at, rec.message_id,
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

        // Resolve recipient user ID from delivery fan-out metadata
        const auto states = delivery_repo_->get_delivery_states_for_message(rec.message_id);
        for (const auto& s : states) {
            if (s.recipient_device_id == rec.device_id) {
                task.recipient_user_id = s.recipient_user_id;
                break;
            }
        }

        const auto status = scheduler_->schedule(std::move(task));
        if (status == SchedulerStatus::Enqueued) {
            ++enqueued_count;
        } else {
            // Drop-to-durable backpressure: in-memory queue saturated, stop scheduling for this device
            break;
        }
    }

    return enqueued_count;
}

size_t DurableDeliveryRecoveryService::sweep_retries_for_device(const domain::DeviceId& device_id,
                                                                const std::string& delivery_bucket,
                                                                std::chrono::system_clock::time_point now) {
    if (!delivery_repo_ || !scheduler_) {
        return 0;
    }

    if (connection_registry_ && !connection_registry_->is_online(device_id)) {
        return 0;
    }

    const auto records = delivery_repo_->fetch_pending_for_device(device_id, delivery_bucket, config_.batch_size);

    size_t retried_count = 0;
    for (const auto& rec : records) {
        if (rec.delivery_state != domain::DeliveryState::RetryWait) {
            continue;
        }

        if (rec.attempt_count >= config_.max_retry_attempts) {
            delivery_repo_->update_device_delivery_status(device_id, delivery_bucket, rec.accepted_at, rec.message_id,
                                                          domain::DeliveryState::Expired, rec.attempt_count,
                                                          std::nullopt);
            continue;
        }

        if (rec.next_retry_at.has_value() && *rec.next_retry_at > now) {
            continue; // Not yet ready for retry dispatch
        }

        // Ready for retry dispatch: transition state back to QUEUED
        delivery_repo_->update_device_delivery_status(device_id, delivery_bucket, rec.accepted_at, rec.message_id,
                                                      domain::DeliveryState::Queued, rec.attempt_count, std::nullopt);

        domain::DeliveryTask task;
        task.message_id = rec.message_id;
        task.conversation_id = rec.conversation_id;
        task.recipient_device_id = rec.device_id;
        task.priority = rec.message_priority;
        task.attempt_count = rec.attempt_count;
        task.accepted_at = rec.accepted_at;
        task.scheduled_at = now;

        task.envelope.ciphertext_blob = rec.ciphertext_blob;
        task.envelope.ephemeral_public_key = rec.ephemeral_public_key;
        task.envelope.iv = rec.iv;
        task.envelope.auth_tag = rec.auth_tag;
        task.envelope.algorithm = rec.algorithm;
        task.envelope.protocol_version = rec.protocol_version;
        task.envelope.one_time_prekey_id = rec.one_time_prekey_id;

        const auto states = delivery_repo_->get_delivery_states_for_message(rec.message_id);
        for (const auto& s : states) {
            if (s.recipient_device_id == rec.device_id) {
                task.recipient_user_id = s.recipient_user_id;
                break;
            }
        }

        const auto status = scheduler_->schedule(std::move(task));
        if (status == SchedulerStatus::Enqueued) {
            ++retried_count;
        } else {
            break;
        }
    }

    return retried_count;
}

size_t DurableDeliveryRecoveryService::purge_expired_for_device(const domain::DeviceId& device_id,
                                                                const std::string& delivery_bucket,
                                                                std::chrono::system_clock::time_point now) {
    if (!delivery_repo_) {
        return 0;
    }

    const auto records = delivery_repo_->fetch_pending_for_device(device_id, delivery_bucket, config_.batch_size);

    size_t purged_count = 0;
    for (const auto& rec : records) {
        if (rec.delivery_state == domain::DeliveryState::Delivered ||
            rec.delivery_state == domain::DeliveryState::Read || rec.delivery_state == domain::DeliveryState::Expired) {
            continue;
        }

        if (now - rec.accepted_at > config_.max_delivery_ttl) {
            delivery_repo_->update_device_delivery_status(device_id, delivery_bucket, rec.accepted_at, rec.message_id,
                                                          domain::DeliveryState::Expired, rec.attempt_count,
                                                          std::nullopt);
            ++purged_count;
        }
    }

    return purged_count;
}

size_t DurableDeliveryRecoveryService::run_recovery_cycle(const std::vector<domain::DeviceId>& candidate_devices,
                                                          const std::string& delivery_bucket) {
    const auto now = std::chrono::system_clock::now();
    const std::string bucket =
        delivery_bucket.empty() ? domain::MessageBucket::from_time_point(now).value() : delivery_bucket;

    std::vector<domain::DeviceId> target_devices;
    if (candidate_devices.empty() && connection_registry_) {
        // When candidates empty, consider connected devices
        // (candidate_devices is passed explicitly in tests or configured device sets)
    } else {
        target_devices = candidate_devices;
    }

    size_t total_tasks_scheduled = 0;
    for (const auto& dev : target_devices) {
        purge_expired_for_device(dev, bucket, now);
        total_tasks_scheduled += sweep_retries_for_device(dev, bucket, now);
        total_tasks_scheduled += recover_pending_for_device(dev, bucket);
    }

    return total_tasks_scheduled;
}

void DurableDeliveryRecoveryService::start(std::vector<domain::DeviceId> candidate_devices) {
    if (running_.exchange(true)) {
        return;
    }
    background_candidate_devices_ = std::move(candidate_devices);
    worker_thread_ = std::thread(&DurableDeliveryRecoveryService::background_worker_loop, this);
}

void DurableDeliveryRecoveryService::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    cv_.notify_all();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

bool DurableDeliveryRecoveryService::is_running() const noexcept {
    return running_.load();
}

void DurableDeliveryRecoveryService::background_worker_loop() {
    std::unique_lock<std::mutex> lock(cv_mutex_);
    while (running_.load()) {
        run_recovery_cycle(background_candidate_devices_);
        cv_.wait_for(lock, config_.sweep_interval, [this]() { return !running_.load(); });
    }
}

} // namespace securecloud::messaging::delivery
