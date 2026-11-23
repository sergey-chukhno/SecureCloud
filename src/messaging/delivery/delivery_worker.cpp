#include "delivery/delivery_worker.hpp"

#include "audit/canonical_audit_mapper.hpp"
#include "domain/audit_event.hpp"
#include "domain/audit_event_id.hpp"
#include "domain/message_bucket.hpp"

#include <nlohmann/json.hpp>
#include <sstream>
#include <utility>

namespace securecloud::messaging::delivery {

namespace {

void stage_delivery_failure_audit(repository::IMessagingAuditOutboxRepository* audit_repo,
                                  const domain::DeliveryTask& task, std::chrono::system_clock::time_point now,
                                  std::string_view reason) {
    if (audit_repo == nullptr) {
        return;
    }

    const nlohmann::json meta = {
        {"conversation_id", task.conversation_id.to_string()},
        {"recipient_device_id", task.recipient_device_id.str()},
        {"attempts", task.attempt_count},
        {"reason", reason},
    };

    domain::MessagingAuditEvent event{
        .event_id = domain::generate_message_audit_event_id(task.message_id, task.recipient_device_id,
                                                            domain::MessagingAuditEventType::MessageDeliveryFailed),
        .event_type = domain::MessagingAuditEventType::MessageDeliveryFailed,
        .severity = domain::MessagingAuditSeverity::Warning,
        .occurred_at = now,
        .actor_user_id = {},
        .actor_device_id = {},
        .target_resource = task.message_id.to_string(),
        .payload_json = meta.dump(),
        .correlation_id = {},
    };
    audit::stage_canonical_audit_event(audit_repo, event, task.conversation_id.to_string());
}

} // namespace

DeliveryWorker::DeliveryWorker(std::shared_ptr<BoundedDeliveryScheduler> scheduler,
                               std::shared_ptr<IDeviceConnectionRegistry> connection_registry,
                               std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo,
                               std::shared_ptr<repository::IOutboxRepository> outbox_repo,
                               std::shared_ptr<repository::IMessagingAuditOutboxRepository> audit_repo,
                               std::shared_ptr<service::DeliveryRetryPolicy> retry_policy, DeliveryWorkerConfig config)
    : scheduler_(std::move(scheduler)), connection_registry_(std::move(connection_registry)),
      delivery_repo_(std::move(delivery_repo)), outbox_repo_(std::move(outbox_repo)),
      audit_repo_(std::move(audit_repo)), retry_policy_(std::move(retry_policy)), config_(config) {}

DeliveryWorker::~DeliveryWorker() {
    stop();
}

void DeliveryWorker::start() {
    if (running_.exchange(true, std::memory_order_acq_rel)) {
        return;
    }

    workers_.reserve(config_.worker_threads);
    for (size_t i = 0; i < config_.worker_threads; ++i) {
        workers_.emplace_back(&DeliveryWorker::worker_loop, this);
    }
}

void DeliveryWorker::stop() {
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    if (scheduler_) {
        scheduler_->shutdown();
    }

    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    workers_.clear();
}

bool DeliveryWorker::is_running() const noexcept {
    return running_.load(std::memory_order_acquire);
}

void DeliveryWorker::worker_loop() {
    while (running_.load(std::memory_order_acquire)) {
        process_single_task(config_.poll_timeout);
    }
}

bool DeliveryWorker::process_single_task(std::chrono::milliseconds poll_timeout) {
    if (!scheduler_) {
        return false;
    }

    auto task_opt = scheduler_->dequeue(poll_timeout);
    if (!task_opt.has_value()) {
        return false;
    }

    auto task = std::move(*task_opt);
    const std::string delivery_bucket = domain::MessageBucket::from_time_point(task.accepted_at).value();

    std::shared_ptr<IDeviceDeliveryChannel> channel;
    if (connection_registry_) {
        channel = connection_registry_->get_channel(task.recipient_device_id);
    }

    if (!channel || !channel->is_active()) {
        if (delivery_repo_) {
            delivery_repo_->update_device_delivery_status(task.recipient_device_id, delivery_bucket, task.accepted_at,
                                                          task.message_id, domain::DeliveryState::Queued,
                                                          task.attempt_count, std::nullopt);
        }
        return true;
    }

    if (delivery_repo_) {
        delivery_repo_->update_device_delivery_status(task.recipient_device_id, delivery_bucket, task.accepted_at,
                                                      task.message_id, domain::DeliveryState::Delivering,
                                                      task.attempt_count, std::nullopt);
    }

    const auto attempt_result = channel->send_envelope(task, config_.send_timeout);

    switch (attempt_result) {
    case domain::DeliveryAttemptResult::Success: {
        const auto delivered_at = std::chrono::system_clock::now();
        if (delivery_repo_) {
            delivery_repo_->record_delivery_ack(task.message_id, task.recipient_device_id, delivered_at);
            delivery_repo_->update_device_delivery_status(task.recipient_device_id, delivery_bucket, task.accepted_at,
                                                          task.message_id, domain::DeliveryState::Delivered,
                                                          task.attempt_count, std::nullopt);
        }

        if (outbox_repo_) {
            domain::ConversationOutboxEvent ack_event;
            ack_event.event_id = domain::MessageId::generate_v7().to_string();
            ack_event.conversation_id = task.conversation_id;
            ack_event.event_type = domain::ConversationOutboxEventType::MessageDelivered;
            ack_event.created_at = delivered_at;

            const auto delivered_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(delivered_at.time_since_epoch()).count();
            std::ostringstream ss;
            ss << "{\"message_id\":\"" << task.message_id.to_string() << "\","
               << "\"recipient_device_id\":\"" << task.recipient_device_id.str() << "\","
               << "\"recipient_user_id\":\"" << task.recipient_user_id.str() << "\","
               << "\"delivered_at_unix_ms\":" << delivered_ms << "}";
            ack_event.payload_json = ss.str();

            outbox_repo_->enqueue_event(ack_event);
        }

        if (audit_repo_) {
            const nlohmann::json meta = {
                {"conversation_id", task.conversation_id.to_string()},
                {"attempt_count", task.attempt_count},
            };
            domain::MessagingAuditEvent event{
                .event_id = domain::generate_message_audit_event_id(task.message_id, task.recipient_device_id,
                                                                    domain::MessagingAuditEventType::MessageDelivered),
                .event_type = domain::MessagingAuditEventType::MessageDelivered,
                .severity = domain::MessagingAuditSeverity::Info,
                .occurred_at = delivered_at,
                .actor_user_id = task.recipient_user_id,
                .actor_device_id = task.recipient_device_id,
                .target_resource = task.message_id.to_string(),
                .payload_json = meta.dump(),
                .correlation_id = {},
            };
            audit::stage_canonical_audit_event(audit_repo_.get(), event, task.conversation_id.to_string());
        }
        break;
    }

    case domain::DeliveryAttemptResult::RecipientOffline: {
        if (delivery_repo_) {
            delivery_repo_->update_device_delivery_status(task.recipient_device_id, delivery_bucket, task.accepted_at,
                                                          task.message_id, domain::DeliveryState::Queued,
                                                          task.attempt_count, std::nullopt);
        }
        break;
    }

    case domain::DeliveryAttemptResult::TransientFailure: {
        task.attempt_count++;
        const auto now = std::chrono::system_clock::now();
        const auto expires_at = task.expires_at.value_or(now + std::chrono::hours(24 * 30));

        const bool can_retry =
            retry_policy_ && retry_policy_->is_retryable(attempt_result, task.attempt_count, expires_at);

        if (can_retry) {
            const auto delay = retry_policy_->compute_next_delay(task.attempt_count);
            const auto next_retry = now + delay;
            task.scheduled_at = next_retry;

            if (delivery_repo_) {
                delivery_repo_->update_device_delivery_status(
                    task.recipient_device_id, delivery_bucket, task.accepted_at, task.message_id,
                    domain::DeliveryState::RetryWait, task.attempt_count, next_retry);
            }

            scheduler_->schedule(std::move(task));
        } else {
            if (delivery_repo_) {
                delivery_repo_->update_device_delivery_status(
                    task.recipient_device_id, delivery_bucket, task.accepted_at, task.message_id,
                    domain::DeliveryState::Expired, task.attempt_count, std::nullopt);
            }
            stage_delivery_failure_audit(audit_repo_.get(), task, now, "MAX_RETRIES_EXHAUSTED");
        }
        break;
    }

    case domain::DeliveryAttemptResult::TerminalFailure: {
        const auto now = std::chrono::system_clock::now();
        if (delivery_repo_) {
            delivery_repo_->update_device_delivery_status(task.recipient_device_id, delivery_bucket, task.accepted_at,
                                                          task.message_id, domain::DeliveryState::Expired,
                                                          task.attempt_count, std::nullopt);
        }

        stage_delivery_failure_audit(audit_repo_.get(), task, now, "TERMINAL_FAILURE");
        break;
    }
    }

    return true;
}

} // namespace securecloud::messaging::delivery
