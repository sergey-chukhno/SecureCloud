#include "auth/audit/auth_outbox_relay.hpp"

#include "auth/audit/auth_audit_mapper.hpp"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <random>
#include <stdexcept>
#include <unordered_set>
#include <utility>
#include <vector>

namespace securecloud::auth::audit {

namespace {

constexpr size_t kMaxAuditBatchSize = 100;

[[nodiscard]] std::string format_rpc_error(const AuditBatchSubmitResult& result) {
    if (!result.status.error_message().empty()) {
        return "gRPC error (" + std::to_string(static_cast<int>(result.status.error_code())) +
               "): " + result.status.error_message();
    }
    return "gRPC error code " + std::to_string(static_cast<int>(result.status.error_code()));
}

} // namespace

AuthOutboxRelay::AuthOutboxRelay(std::shared_ptr<repository::IAuthOutboxRepository> repository,
                                 std::shared_ptr<IAuthAuditClient> audit_client,
                                 AuthOutboxRelayConfig config,
                                 std::string producer_instance)
    : repository_(std::move(repository)),
      audit_client_(std::move(audit_client)),
      config_(config),
      producer_instance_(producer_instance.empty() ? "auth" : std::move(producer_instance)) {
    if (!repository_) {
        throw std::invalid_argument("AuthOutboxRelay repository must not be null");
    }
    if (!audit_client_) {
        throw std::invalid_argument("AuthOutboxRelay audit_client must not be null");
    }

    if (config_.batch_size > kMaxAuditBatchSize) {
        config_.batch_size = kMaxAuditBatchSize;
    }
    if (config_.poll_interval.count() <= 0) {
        config_.poll_interval = std::chrono::milliseconds(500);
    }
    if (config_.lease_duration.count() <= 0) {
        config_.lease_duration = std::chrono::seconds(30);
    }
    if (config_.initial_backoff.count() < 0) {
        config_.initial_backoff = std::chrono::milliseconds(0);
    }
    if (config_.max_backoff < config_.initial_backoff) {
        config_.max_backoff = config_.initial_backoff;
    }
    if (config_.backoff_multiplier < 1.0) {
        config_.backoff_multiplier = 1.0;
    }
    config_.jitter_ratio = std::clamp(config_.jitter_ratio, 0.0, 1.0);
}

AuthOutboxRelay::~AuthOutboxRelay() {
    stop();
}

void AuthOutboxRelay::start() {
    if (running_.exchange(true, std::memory_order_acq_rel)) {
        return;
    }
    worker_thread_ = std::thread(&AuthOutboxRelay::run, this);
}

void AuthOutboxRelay::stop() {
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(cv_mutex_);
        wake_requested_.store(true, std::memory_order_relaxed);
    }
    cv_.notify_all();

    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }

    drain_on_shutdown();
}

void AuthOutboxRelay::notify() {
    {
        std::lock_guard<std::mutex> lock(cv_mutex_);
        wake_requested_.store(true, std::memory_order_relaxed);
    }
    cv_.notify_one();
}

bool AuthOutboxRelay::is_running() const noexcept {
    return running_.load(std::memory_order_acquire);
}

std::chrono::milliseconds AuthOutboxRelay::compute_backoff_delay(uint32_t failure_attempt) const noexcept {
    if (failure_attempt == 0 || config_.initial_backoff.count() == 0) {
        return std::chrono::milliseconds(0);
    }

    const double max_ms = static_cast<double>(config_.max_backoff.count());
    double base_ms = static_cast<double>(config_.initial_backoff.count());

    for (uint32_t i = 1; i < failure_attempt && base_ms < max_ms; ++i) {
        base_ms = std::min(max_ms, base_ms * config_.backoff_multiplier);
    }

    if (config_.jitter_ratio > 0.0) {
        thread_local std::mt19937 rng{std::random_device{}()};
        std::uniform_real_distribution<double> dist(-config_.jitter_ratio, config_.jitter_ratio);
        base_ms *= (1.0 + dist(rng));
    }

    const double clamped_ms = std::clamp(base_ms, 0.0, max_ms);
    return std::chrono::milliseconds(static_cast<int64_t>(std::llround(clamped_ms)));
}

size_t AuthOutboxRelay::poll_and_dispatch() {
    if (config_.batch_size == 0) {
        return 0;
    }

    std::vector<domain::AuthOutboxEntity> leased_events;
    try {
        leased_events = repository_->fetch_and_lease_pending_batch(config_.batch_size, config_.lease_duration);
    } catch (const std::exception& ex) {
        std::cerr << "[SecureCloud] [auth-outbox-relay] Failed to fetch and lease batch: " << ex.what() << "\n";
        ++consecutive_failures_;
        return 0;
    } catch (...) {
        std::cerr << "[SecureCloud] [auth-outbox-relay] Unknown error fetching outbox batch\n";
        ++consecutive_failures_;
        return 0;
    }

    if (leased_events.empty()) {
        return 0;
    }

    std::vector<domain::AuthOutboxEntity> valid_entities;
    std::vector<::securecloud::audit::v1::AuditEventProto> proto_batch;
    valid_entities.reserve(leased_events.size());
    proto_batch.reserve(leased_events.size());

    // Translate leased records to canonical AuditEventProto; quarantine poison pills immediately.
    for (auto& entity : leased_events) {
        try {
            auto proto = AuthAuditMapper::to_proto(entity, producer_instance_);
            proto_batch.push_back(std::move(proto));
            valid_entities.push_back(std::move(entity));
        } catch (const std::exception& ex) {
            try {
                repository_->mark_quarantined(entity.event_id, ex.what());
            } catch (const std::exception& repo_ex) {
                std::cerr << "[SecureCloud] [auth-outbox-relay] Failed to quarantine malformed event "
                          << entity.event_id.to_string() << ": " << repo_ex.what() << "\n";
            }
        }
    }

    if (proto_batch.empty()) {
        consecutive_failures_ = 0;
        return leased_events.size();
    }

    AuditBatchSubmitResult submit_result;
    try {
        submit_result = audit_client_->submit_batch(proto_batch);
    } catch (const std::exception& ex) {
        submit_result.rpc_success = false;
        submit_result.status = grpc::Status(grpc::StatusCode::UNAVAILABLE, ex.what());
    } catch (...) {
        submit_result.rpc_success = false;
        submit_result.status = grpc::Status(grpc::StatusCode::UNAVAILABLE, "Unknown client exception");
    }

    if (submit_result.rpc_success) {
        consecutive_failures_ = 0;

        std::unordered_set<std::string> rejected_ids;
        rejected_ids.reserve(submit_result.rejected_event_ids.size());
        for (const auto& rejected_id : submit_result.rejected_event_ids) {
            rejected_ids.insert(rejected_id);
        }

        for (const auto& entity : valid_entities) {
            const std::string id_str = entity.event_id.to_string();
            try {
                if (rejected_ids.contains(id_str)) {
                    repository_->mark_quarantined(entity.event_id, "Permanently rejected by AuditIngestionService");
                } else {
                    repository_->mark_published(entity.event_id);
                }
            } catch (const std::exception& ex) {
                std::cerr << "[SecureCloud] [auth-outbox-relay] Failed to update acknowledgement state for event "
                          << id_str << ": " << ex.what() << "\n";
            }
        }
    } else {
        ++consecutive_failures_;
        const std::string error_detail = format_rpc_error(submit_result);

        // Transient / ambiguous failure: retain in PENDING, clear lease, record last_error for retry
        for (const auto& entity : valid_entities) {
            try {
                repository_->mark_failed(entity.event_id, error_detail);
            } catch (const std::exception& ex) {
                std::cerr << "[SecureCloud] [auth-outbox-relay] Failed to record retry state for event "
                          << entity.event_id.to_string() << ": " << ex.what() << "\n";
            }
        }
    }

    return leased_events.size();
}

size_t AuthOutboxRelay::purge_old_published_records() {
    if (config_.purge_batch_size == 0) {
        return 0;
    }

    try {
        const auto cutoff = std::chrono::system_clock::now() - config_.published_retention;
        return repository_->purge_published_older_than(cutoff, config_.purge_batch_size);
    } catch (const std::exception& ex) {
        std::cerr << "[SecureCloud] [auth-outbox-relay] Failed to purge old published records: " << ex.what() << "\n";
        return 0;
    } catch (...) {
        std::cerr << "[SecureCloud] [auth-outbox-relay] Unknown error purging old published records\n";
        return 0;
    }
}

void AuthOutboxRelay::run() {
    auto last_purge = std::chrono::steady_clock::now();

    while (running_.load(std::memory_order_acquire)) {
        wake_requested_.store(false, std::memory_order_relaxed);

        const size_t processed = poll_and_dispatch();

        const auto now_steady = std::chrono::steady_clock::now();
        if (config_.purge_interval.count() > 0 && (now_steady - last_purge) >= config_.purge_interval) {
            (void)purge_old_published_records();
            last_purge = now_steady;
        }

        if (!running_.load(std::memory_order_acquire)) {
            break;
        }

        if (consecutive_failures_ > 0) {
            const auto backoff = compute_backoff_delay(consecutive_failures_);
            if (backoff.count() > 0) {
                std::unique_lock<std::mutex> lock(cv_mutex_);
                cv_.wait_for(lock, backoff, [this]() { return !running_.load(std::memory_order_acquire); });
            }
            continue;
        }

        if (processed == 0) {
            std::unique_lock<std::mutex> lock(cv_mutex_);
            cv_.wait_for(lock, config_.poll_interval, [this]() {
                return !running_.load(std::memory_order_acquire) || wake_requested_.load(std::memory_order_relaxed);
            });
        }
    }
}

void AuthOutboxRelay::drain_on_shutdown() {
    if (config_.shutdown_drain_timeout.count() <= 0) {
        return;
    }

    const auto deadline = std::chrono::steady_clock::now() + config_.shutdown_drain_timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        const size_t processed = poll_and_dispatch();
        if (processed == 0 || consecutive_failures_ > 0) {
            break;
        }
    }
}

} // namespace securecloud::auth::audit
