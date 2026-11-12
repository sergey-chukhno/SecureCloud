#include "auth/service/outbox_relay_worker.hpp"
#include "auth/service/outbox_event_mapper.hpp"

#include <algorithm>
#include <grpcpp/grpcpp.h>
#include <random>
#include <stdexcept>
#include <unordered_set>
#include <utility>
#include <vector>

namespace securecloud::auth::service {

namespace {

[[nodiscard]] bool is_non_retryable_grpc_status(grpc::StatusCode code) noexcept {
    switch (code) {
    case grpc::StatusCode::INVALID_ARGUMENT:
    case grpc::StatusCode::FAILED_PRECONDITION:
    case grpc::StatusCode::OUT_OF_RANGE:
    case grpc::StatusCode::UNIMPLEMENTED:
        return true;
    default:
        return false;
    }
}

[[nodiscard]] std::chrono::milliseconds compute_backoff_with_jitter(uint32_t consecutive_failures,
                                                                    std::chrono::milliseconds base,
                                                                    std::chrono::milliseconds max_backoff) {
    const uint32_t shift = std::min<uint32_t>(consecutive_failures, 10);
    const auto raw_ms = std::min<int64_t>(base.count() * (int64_t{1} << shift), max_backoff.count());
    const int64_t min_jitter = std::max<int64_t>(1, raw_ms / 2);

    thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<int64_t> dist(min_jitter, std::max<int64_t>(min_jitter, raw_ms));
    return std::chrono::milliseconds{dist(rng)};
}

} // namespace

OutboxRelayWorker::OutboxRelayWorker(
    std::shared_ptr<repository::IAuthOutboxRepository> outbox_repo,
    std::shared_ptr<securecloud::audit::v1::AuditIngestionService::StubInterface> audit_stub, OutboxRelayConfig config)
    : outbox_repo_(std::move(outbox_repo)), audit_stub_(std::move(audit_stub)), config_(config) {
    if (!outbox_repo_) {
        throw std::invalid_argument("OutboxRelayWorker requires non-null IAuthOutboxRepository");
    }
    if (!audit_stub_) {
        throw std::invalid_argument("OutboxRelayWorker requires non-null AuditIngestionService stub");
    }
}

OutboxRelayWorker::~OutboxRelayWorker() {
    stop();
}

void OutboxRelayWorker::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (running_) {
        return;
    }
    stop_requested_ = false;
    running_ = true;
    worker_thread_ = std::thread(&OutboxRelayWorker::run_loop, this);
}

void OutboxRelayWorker::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!running_) {
            return;
        }
        stop_requested_ = true;
    }
    cv_.notify_all();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
    std::lock_guard<std::mutex> lock(mutex_);
    running_ = false;
}

void OutboxRelayWorker::notify_new_events() noexcept {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        wakeup_requested_ = true;
    }
    cv_.notify_one();
}

std::size_t OutboxRelayWorker::drain_once() {
    auto batch = outbox_repo_->fetch_and_lease_pending_batch(config_.batch_size, config_.lease_duration);
    if (batch.empty()) {
        return 0;
    }

    securecloud::audit::v1::BatchSubmitAuditEventsRequest request;
    std::vector<domain::AuthOutboxEntity> valid_entities;
    valid_entities.reserve(batch.size());

    for (const auto& entity : batch) {
        if (entity.retry_count > config_.max_retries) {
            outbox_repo_->mark_quarantined(entity.event_id, "Exceeded maximum outbox delivery retry attempts");
            metrics_.events_quarantined.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        try {
            auto proto = OutboxEventMapper::to_audit_proto(entity);
            *request.add_events() = std::move(proto);
            valid_entities.push_back(entity);
        } catch (const std::exception& ex) {
            // Payload JSON corrompu : quarantaine immédiate pour ne pas bloquer le batch
            outbox_repo_->mark_quarantined(entity.event_id,
                                           std::string("Corrupted outbox payload_json: ") + ex.what());
            metrics_.events_quarantined.fetch_add(1, std::memory_order_relaxed);
        }
    }

    if (valid_entities.empty()) {
        metrics_.batches_processed.fetch_add(1, std::memory_order_relaxed);
        return batch.size();
    }

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + config_.rpc_timeout);

    securecloud::audit::v1::BatchSubmitAuditEventsResponse response;
    const grpc::Status status = audit_stub_->BatchSubmitAuditEvents(&context, request, &response);

    if (!status.ok()) {
        const std::string err_msg =
            "gRPC status " + std::to_string(static_cast<int>(status.error_code())) + ": " + status.error_message();
        const bool non_retryable = is_non_retryable_grpc_status(status.error_code());

        for (const auto& entity : valid_entities) {
            if (non_retryable || entity.retry_count >= config_.max_retries) {
                outbox_repo_->mark_quarantined(entity.event_id, err_msg);
                metrics_.events_quarantined.fetch_add(1, std::memory_order_relaxed);
            } else {
                outbox_repo_->mark_failed(entity.event_id, err_msg);
                metrics_.events_failed.fetch_add(1, std::memory_order_relaxed);
            }
        }

        metrics_.batches_processed.fetch_add(1, std::memory_order_relaxed);
        return batch.size();
    }

    std::unordered_set<std::string> rejected_ids;
    rejected_ids.reserve(static_cast<std::size_t>(response.rejected_event_ids_size()));
    for (const auto& rej_id : response.rejected_event_ids()) {
        rejected_ids.insert(rej_id);
    }

    for (const auto& entity : valid_entities) {
        const std::string id_str = entity.event_id.to_string();
        if (rejected_ids.contains(id_str)) {
            outbox_repo_->mark_quarantined(entity.event_id, "Rejected by AuditIngestionService schema/policy validation");
            metrics_.events_quarantined.fetch_add(1, std::memory_order_relaxed);
        } else {
            outbox_repo_->mark_published(entity.event_id);
            metrics_.events_published.fetch_add(1, std::memory_order_relaxed);
        }
    }

    metrics_.batches_processed.fetch_add(1, std::memory_order_relaxed);
    return batch.size();
}

void OutboxRelayWorker::maybe_run_cleanup() {
    const auto now_steady = std::chrono::steady_clock::now();
    if (now_steady - last_cleanup_ < config_.cleanup_interval) {
        return;
    }
    last_cleanup_ = now_steady;

    try {
        const auto cutoff = std::chrono::system_clock::now() - config_.published_retention;
        const std::size_t purged = outbox_repo_->purge_published_older_than(cutoff, config_.cleanup_batch_size);
        if (purged > 0) {
            metrics_.events_purged.fetch_add(purged, std::memory_order_relaxed);
        }
    } catch (...) {
        // La purge est best-effort et ne doit jamais interrompre la boucle de relais
    }
}

void OutboxRelayWorker::run_loop() {
    uint32_t consecutive_errors = 0;

    while (true) {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            if (stop_requested_) {
                break;
            }
        }

        std::size_t processed = 0;
        bool had_error = false;
        try {
            processed = drain_once();
            consecutive_errors = 0;
        } catch (...) {
            had_error = true;
            ++consecutive_errors;
        }

        maybe_run_cleanup();

        // Si un batch plein a été traité sans erreur, on enchaîne immédiatement le suivant
        if (!had_error && processed >= config_.batch_size) {
            continue;
        }

        const auto wait_duration =
            had_error ? compute_backoff_with_jitter(consecutive_errors, config_.poll_interval, config_.max_backoff)
                      : config_.poll_interval;

        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait_for(lock, wait_duration, [this]() { return stop_requested_ || wakeup_requested_; });
        wakeup_requested_ = false;
        if (stop_requested_) {
            break;
        }
    }
}

} // namespace securecloud::auth::service
