#include "application/managers/delivery_retry_engine.hpp"

#include <algorithm>
#include <cmath>

namespace securecloud::client::application::managers {

DeliveryRetryEngine::DeliveryRetryEngine(domain::RetryPolicyConfig config)
    : config_(config), rng_(std::random_device{}()) {}

void DeliveryRetryEngine::set_config(const domain::RetryPolicyConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
}

domain::RetryPolicyConfig DeliveryRetryEngine::config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

std::chrono::milliseconds DeliveryRetryEngine::compute_backoff(uint32_t attempt) {
    std::lock_guard<std::mutex> lock(mutex_);
    const uint32_t exp_shift = attempt > 0 ? std::min<uint32_t>(attempt - 1, 20) : 0;
    const double base_ms =
        static_cast<double>(config_.initial_backoff.count()) * static_cast<double>(1ULL << exp_shift);
    const double capped_ms = std::min(base_ms, static_cast<double>(config_.max_backoff.count()));

    const double clamped_jitter = std::clamp(config_.jitter_ratio, 0.0, 0.95);
    std::uniform_real_distribution<double> dist(1.0 - clamped_jitter, 1.0 + clamped_jitter);
    const double jittered_ms = std::max(1.0, capped_ms * dist(rng_));

    return std::chrono::milliseconds(static_cast<int64_t>(std::llround(jittered_ms)));
}

void DeliveryRetryEngine::enqueue(domain::ConversationId conversation_id, domain::MessageId message_id,
                                  interfaces::FanOutSubmissionRequest request,
                                  std::chrono::steady_clock::time_point now, std::string outbox_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (outbox_id.empty()) {
        outbox_id = "msg-" + message_id.value();
    }
    for (const auto& existing : queue_) {
        if ((!outbox_id.empty() && existing.outbox_id == outbox_id) || existing.message_id == message_id) {
            return;
        }
    }

    const uint32_t initial_attempt = 1;
    const uint32_t exp_shift = 0;
    const double base_ms =
        static_cast<double>(config_.initial_backoff.count()) * static_cast<double>(1ULL << exp_shift);
    const double capped_ms = std::min(base_ms, static_cast<double>(config_.max_backoff.count()));
    const double clamped_jitter = std::clamp(config_.jitter_ratio, 0.0, 0.95);
    std::uniform_real_distribution<double> dist(1.0 - clamped_jitter, 1.0 + clamped_jitter);
    const auto delay =
        std::chrono::milliseconds(static_cast<int64_t>(std::llround(std::max(1.0, capped_ms * dist(rng_)))));

    const int32_t prio = request.priority;
    queue_.push_back(RetryQueueEntry{
        .conversation_id = std::move(conversation_id),
        .message_id = std::move(message_id),
        .request = std::move(request),
        .priority = prio,
        .outbox_id = std::move(outbox_id),
        .attempt_count = initial_attempt,
        .enqueued_at = now,
        .next_retry_at = now + delay,
        .expires_at = now + config_.expiration_ttl,
    });
}

void DeliveryRetryEngine::hydrate_entry(RetryQueueEntry entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (entry.outbox_id.empty()) {
        entry.outbox_id = "msg-" + entry.message_id.value();
    }
    for (const auto& existing : queue_) {
        if ((!entry.outbox_id.empty() && existing.outbox_id == entry.outbox_id) ||
            (entry.outbox_id.empty() && existing.message_id == entry.message_id)) {
            return;
        }
    }
    queue_.push_back(std::move(entry));
}

bool DeliveryRetryEngine::remove(const domain::MessageId& message_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto prev_size = queue_.size();
    queue_.erase(std::remove_if(queue_.begin(), queue_.end(),
                                [&](const RetryQueueEntry& e) { return e.message_id == message_id; }),
                 queue_.end());
    return queue_.size() != prev_size;
}

bool DeliveryRetryEngine::remove_by_outbox_id(std::string_view outbox_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto prev_size = queue_.size();
    queue_.erase(std::remove_if(queue_.begin(), queue_.end(),
                                [&](const RetryQueueEntry& e) { return e.outbox_id == outbox_id; }),
                 queue_.end());
    return queue_.size() != prev_size;
}

std::size_t DeliveryRetryEngine::pending_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

std::size_t DeliveryRetryEngine::process_due(std::chrono::steady_clock::time_point now, const SubmitFn& submit_fn,
                                             const ExpireFn& expire_fn, const UpdateFn& update_fn) {
    std::vector<RetryQueueEntry> due;
    std::vector<RetryQueueEntry> expired;
    domain::RetryPolicyConfig cfg;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        cfg = config_;
        std::vector<RetryQueueEntry> remaining;
        remaining.reserve(queue_.size());

        for (auto& entry : queue_) {
            if (now >= entry.expires_at || entry.attempt_count >= cfg.max_attempts) {
                expired.push_back(std::move(entry));
            } else if (now >= entry.next_retry_at) {
                due.push_back(std::move(entry));
            } else {
                remaining.push_back(std::move(entry));
            }
        }
        queue_ = std::move(remaining);
    }

    std::sort(due.begin(), due.end(), [](const RetryQueueEntry& a, const RetryQueueEntry& b) {
        if (a.priority != b.priority) {
            return a.priority > b.priority;
        }
        if (a.enqueued_at != b.enqueued_at) {
            return a.enqueued_at < b.enqueued_at;
        }
        if (a.outbox_id != b.outbox_id) {
            return a.outbox_id < b.outbox_id;
        }
        return a.message_id.value() < b.message_id.value();
    });

    std::size_t completed_count = 0;
    for (const auto& exp : expired) {
        if (expire_fn) {
            expire_fn(exp.conversation_id, exp.message_id);
        }
        ++completed_count;
    }

    for (auto& entry : due) {
        auto res = submit_fn ? submit_fn(entry.request)
                             : ClientResult<std::string>::error(ClientError::internal_error("No submit handler"));
        if (res.is_ok()) {
            ++completed_count;
            continue;
        }

        ++entry.attempt_count;
        if (now >= entry.expires_at || entry.attempt_count >= cfg.max_attempts ||
            res.error().category() != ClientErrorCategory::Network) {
            if (expire_fn) {
                expire_fn(entry.conversation_id, entry.message_id);
            }
            ++completed_count;
            continue;
        }

        const auto delay = compute_backoff(entry.attempt_count);
        entry.next_retry_at = now + delay;
        if (update_fn) {
            update_fn(entry, res.error());
        }
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push_back(std::move(entry));
    }

    return completed_count;
}

} // namespace securecloud::client::application::managers
