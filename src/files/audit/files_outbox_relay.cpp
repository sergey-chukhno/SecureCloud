#include "files/audit/files_outbox_relay.hpp"

#include "files/audit/grpc_audit_client.hpp"

#include <algorithm>
#include <cmath>
#include <unordered_set>
#include <utility>
#include <vector>

namespace securecloud::files::audit {

namespace {

bool is_permanent_rpc_rejection(grpc::StatusCode code) noexcept {
    return code == grpc::StatusCode::INVALID_ARGUMENT || code == grpc::StatusCode::ALREADY_EXISTS;
}

bool is_security_auth_fault(grpc::StatusCode code) noexcept {
    return code == grpc::StatusCode::PERMISSION_DENIED || code == grpc::StatusCode::UNAUTHENTICATED;
}

} // namespace

FilesOutboxRelay::FilesOutboxRelay(std::shared_ptr<IFilesOutboxRepository> outbox_repo,
                                   std::shared_ptr<IFilesAuditClient> audit_client, FilesOutboxRelayConfig config,
                                   std::string producer_instance, FilesOutboxMetrics* metrics,
                                   FilesOutboxDiagnostics* diagnostics)
    : outbox_repo_(std::move(outbox_repo)), audit_client_(std::move(audit_client)), config_(config),
      producer_instance_(std::move(producer_instance)), metrics_(metrics), diagnostics_(diagnostics),
      rng_(std::random_device{}()) {
    if (config_.batch_size == 0) {
        config_.batch_size = 50;
    }
    config_.batch_size = std::min<size_t>(config_.batch_size, GrpcAuditClient::k_max_batch_size);
    if (producer_instance_.empty()) {
        producer_instance_ = "files-1";
    }
}

FilesOutboxRelay::~FilesOutboxRelay() {
    stop();
}

void FilesOutboxRelay::start() {
    if (running_.exchange(true)) {
        return;
    }
    stopping_.store(false);
    worker_thread_ = std::thread(&FilesOutboxRelay::run, this);
}

void FilesOutboxRelay::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    stopping_.store(true);
    cv_.notify_all();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

void FilesOutboxRelay::notify() noexcept {
    notified_.store(true, std::memory_order_release);
    cv_.notify_one();
}

bool FilesOutboxRelay::is_running() const noexcept {
    return running_.load();
}

std::chrono::milliseconds FilesOutboxRelay::compute_backoff_delay(uint32_t failure_attempt) const {
    if (failure_attempt == 0) {
        return std::chrono::milliseconds(0);
    }

    const double init_ms = static_cast<double>(std::max<int64_t>(1, config_.initial_backoff.count()));
    const double max_ms = static_cast<double>(std::max<int64_t>(1, config_.max_backoff.count()));
    const double mult = std::max(1.0, config_.backoff_multiplier);
    const double exponent = static_cast<double>(std::min<uint32_t>(failure_attempt - 1, 30));

    double base_ms = std::min(max_ms, init_ms * std::pow(mult, exponent));
    const double jitter = std::clamp(config_.jitter_ratio, 0.0, 1.0);
    if (jitter > 0.0) {
        std::lock_guard<std::mutex> lock(rng_mutex_);
        std::uniform_real_distribution<double> dist(-jitter, jitter);
        base_ms *= (1.0 + dist(rng_));
    }

    const auto clamped_ms = static_cast<int64_t>(std::max(1.0, std::min(max_ms, base_ms)));
    return std::chrono::milliseconds(clamped_ms);
}

size_t FilesOutboxRelay::poll_and_dispatch(size_t batch_size) {
    if (!outbox_repo_ || !audit_client_ || batch_size == 0) {
        return 0;
    }

    const size_t clamped_batch = std::min<size_t>(batch_size, GrpcAuditClient::k_max_batch_size);

    std::vector<FilesOutboxEntity> events;
    try {
        events = outbox_repo_->fetch_and_lease_pending_batch(clamped_batch, config_.lease_duration);
    } catch (const std::exception& ex) {
        if (diagnostics_)
            diagnostics_->log_event(FilesDiagnosticCategory::Lease, "lease_failed", {}, ex.what());
        record_failure_diag(grpc::StatusCode::INTERNAL, ex.what());
        return 0;
    } catch (...) {
        if (diagnostics_)
            diagnostics_->log_event(FilesDiagnosticCategory::Lease, "lease_failed", {}, "unknown exception");
        record_failure_diag(grpc::StatusCode::UNKNOWN, "unknown_lease_exception");
        return 0;
    }

    if (events.empty()) {
        if (metrics_) {
            try {
                metrics_->set_pending(static_cast<int64_t>(outbox_repo_->count_pending()));
                metrics_->set_oldest_pending_age(outbox_repo_->oldest_pending_age_seconds());
            } catch (...) {
            }
        }
        return 0;
    }

    std::vector<FilesOutboxEntity> valid_events;
    std::vector<securecloud::audit::v1::AuditEventProto> valid_protos;
    valid_events.reserve(events.size());
    valid_protos.reserve(events.size());

    const auto now = std::chrono::system_clock::now();
    for (const auto& ev : events) {
        auto mapped = FilesAuditMapper::to_validated_proto(ev, now, producer_instance_);
        if (!mapped.valid) {
            try {
                outbox_repo_->mark_quarantined(ev.event_id, "local_validation_failed: " + mapped.validation_error);
                if (metrics_) {
                    metrics_->events_quarantined.fetch_add(1, std::memory_order_relaxed);
                    metrics_->record_quarantined(FilesOutboxQuarantineReason::Validation);
                }
                if (diagnostics_)
                    diagnostics_->log_event(FilesDiagnosticCategory::Quarantine, "local_validation", {},
                                            mapped.validation_error);
            } catch (const std::exception& ex) {
                if (diagnostics_)
                    diagnostics_->log_event(FilesDiagnosticCategory::Quarantine, "quarantine_update_failed", {},
                                            ex.what());
            } catch (...) {
            }
            continue;
        }
        valid_events.push_back(ev);
        valid_protos.push_back(std::move(mapped.proto));
    }

    if (!valid_protos.empty()) {
        dispatch_chunk(valid_events, valid_protos);
    }

    if (metrics_) {
        try {
            metrics_->set_pending(static_cast<int64_t>(outbox_repo_->count_pending()));
            metrics_->set_oldest_pending_age(outbox_repo_->oldest_pending_age_seconds());
        } catch (...) {
        }
    }

    return events.size();
}

void FilesOutboxRelay::dispatch_chunk(const std::vector<FilesOutboxEntity>& chunk_events,
                                      const std::vector<securecloud::audit::v1::AuditEventProto>& chunk_protos) {
    FilesAuditBatchSubmitResult submit_result;
    try {
        submit_result = audit_client_->submit_batch(chunk_protos);
    } catch (const std::exception& ex) {
        submit_result.rpc_success = false;
        submit_result.status = grpc::Status(grpc::StatusCode::UNAVAILABLE, ex.what());
    } catch (...) {
        submit_result.rpc_success = false;
        submit_result.status = grpc::Status(grpc::StatusCode::UNKNOWN, "unknown_submit_exception");
    }

    if (submit_result.rpc_success) {
        if (metrics_) {
            metrics_->batches_dispatched.fetch_add(1, std::memory_order_relaxed);
            metrics_->record_batch(submit_result.rejected_event_ids.empty() ? FilesOutboxOutcome::Success
                                                                            : FilesOutboxOutcome::Rejected);
        }
        if (diagnostics_)
            diagnostics_->log_event(FilesDiagnosticCategory::Batch, "batch_acknowledged", {}, {}, chunk_events.size());
        consecutive_failures_.store(0, std::memory_order_relaxed);
        record_success_diag();

        std::unordered_set<std::string> rejected_ids(submit_result.rejected_event_ids.begin(),
                                                     submit_result.rejected_event_ids.end());

        for (size_t i = 0; i < chunk_events.size(); ++i) {
            const auto& ev = chunk_events[i];
            try {
                if (rejected_ids.contains(ev.event_id)) {
                    outbox_repo_->mark_quarantined(ev.event_id, "audit_service_rejected");
                    if (metrics_) {
                        metrics_->events_quarantined.fetch_add(1, std::memory_order_relaxed);
                        metrics_->record_quarantined(FilesOutboxQuarantineReason::Rejected);
                    }
                } else {
                    outbox_repo_->mark_published(ev.event_id);
                    if (metrics_) {
                        metrics_->events_published.fetch_add(1, std::memory_order_relaxed);
                        metrics_->record_delivered();
                    }
                }
            } catch (const std::exception& ex) {
                if (diagnostics_)
                    diagnostics_->log_event(FilesDiagnosticCategory::Batch, "state_update_failed", {}, ex.what());
            } catch (...) {
            }
        }
        return;
    }

    const grpc::StatusCode code = submit_result.status.error_code();
    const std::string err_msg =
        submit_result.status.error_message().empty() ? "audit_rpc_failed" : submit_result.status.error_message();

    if (is_permanent_rpc_rejection(code)) {
        if (metrics_) {
            metrics_->batches_dispatched.fetch_add(1, std::memory_order_relaxed);
            metrics_->record_batch(FilesOutboxOutcome::Rejected);
        }
        if (diagnostics_)
            diagnostics_->log_event(FilesDiagnosticCategory::Batch, "batch_rejected", {}, err_msg, chunk_events.size());
        consecutive_failures_.store(0, std::memory_order_relaxed);
        if (chunk_events.size() == 1) {
            try {
                outbox_repo_->mark_quarantined(chunk_events[0].event_id, "audit_permanent_rejection: " + err_msg);
                if (metrics_) {
                    metrics_->events_quarantined.fetch_add(1, std::memory_order_relaxed);
                }
            } catch (...) {
            }
        } else {
            probe_and_isolate_invalid_batch(chunk_events, chunk_protos);
        }
        return;
    }

    if (is_security_auth_fault(code)) {
        if (diagnostics_)
            diagnostics_->log_event(FilesDiagnosticCategory::Outage, "audit_identity_fault", {}, err_msg,
                                    static_cast<uint64_t>(code));
        if (metrics_) {
            metrics_->batches_dispatched.fetch_add(1, std::memory_order_relaxed);
            metrics_->record_batch(FilesOutboxOutcome::Retryable);
            metrics_->record_retry(chunk_events.size());
            metrics_->security_auth_failures.fetch_add(1, std::memory_order_relaxed);
            metrics_->transient_failures.fetch_add(chunk_events.size(), std::memory_order_relaxed);
        }
        consecutive_failures_.store(30, std::memory_order_relaxed);
        record_failure_diag(code, err_msg);

        for (const auto& ev : chunk_events) {
            try {
                outbox_repo_->record_transient_failure(ev.event_id, "security_auth_fault: " + err_msg);
            } catch (...) {
            }
        }
        return;
    }

    consecutive_failures_.fetch_add(1, std::memory_order_relaxed);
    if (metrics_) {
        metrics_->batches_dispatched.fetch_add(1, std::memory_order_relaxed);
        metrics_->record_batch(FilesOutboxOutcome::Retryable);
        metrics_->record_retry(chunk_events.size());
    }
    if (metrics_) {
        metrics_->transient_failures.fetch_add(chunk_events.size(), std::memory_order_relaxed);
    }
    record_failure_diag(code, err_msg);

    for (const auto& ev : chunk_events) {
        try {
            outbox_repo_->record_transient_failure(ev.event_id, err_msg);
        } catch (const std::exception& ex) {
            if (diagnostics_)
                diagnostics_->log_event(FilesDiagnosticCategory::Batch, "retry_record_failed", {}, ex.what());
        } catch (...) {
        }
    }
}

void FilesOutboxRelay::probe_and_isolate_invalid_batch(
    const std::vector<FilesOutboxEntity>& chunk_events,
    const std::vector<securecloud::audit::v1::AuditEventProto>& chunk_protos) {
    for (size_t i = 0; i < chunk_events.size(); ++i) {
        const auto& ev = chunk_events[i];
        std::vector<securecloud::audit::v1::AuditEventProto> single_proto{chunk_protos[i]};

        FilesAuditBatchSubmitResult single_res;
        try {
            single_res = audit_client_->submit_batch(single_proto);
        } catch (const std::exception& ex) {
            single_res.rpc_success = false;
            single_res.status = grpc::Status(grpc::StatusCode::UNAVAILABLE, ex.what());
        } catch (...) {
            single_res.rpc_success = false;
            single_res.status = grpc::Status(grpc::StatusCode::UNKNOWN, "unknown_probe_exception");
        }

        if (single_res.rpc_success) {
            std::unordered_set<std::string> rejected_ids(single_res.rejected_event_ids.begin(),
                                                         single_res.rejected_event_ids.end());
            try {
                if (rejected_ids.contains(ev.event_id)) {
                    outbox_repo_->mark_quarantined(ev.event_id, "audit_service_rejected");
                    if (metrics_) {
                        metrics_->events_quarantined.fetch_add(1, std::memory_order_relaxed);
                    }
                } else {
                    outbox_repo_->mark_published(ev.event_id);
                    if (metrics_) {
                        metrics_->events_published.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            } catch (...) {
            }
            continue;
        }

        const grpc::StatusCode single_code = single_res.status.error_code();
        const std::string single_err =
            single_res.status.error_message().empty() ? "audit_rpc_failed" : single_res.status.error_message();

        if (is_permanent_rpc_rejection(single_code)) {
            try {
                outbox_repo_->mark_quarantined(ev.event_id, "audit_permanent_rejection: " + single_err);
                if (metrics_) {
                    metrics_->events_quarantined.fetch_add(1, std::memory_order_relaxed);
                }
            } catch (...) {
            }
        } else {
            try {
                outbox_repo_->record_transient_failure(ev.event_id, single_err);
                if (metrics_) {
                    metrics_->transient_failures.fetch_add(1, std::memory_order_relaxed);
                }
            } catch (...) {
            }
        }
    }
}

size_t FilesOutboxRelay::purge_old_published_records() {
    if (!outbox_repo_) {
        return 0;
    }

    const auto cutoff = std::chrono::system_clock::now() - config_.published_retention;
    try {
        const size_t purged = outbox_repo_->purge_published_older_than(cutoff, config_.purge_batch_size);
        if (metrics_ && purged > 0) {
            metrics_->record_purged(purged);
        }
        if (diagnostics_) {
            std::lock_guard<std::mutex> lock(diagnostics_->mutex);
            diagnostics_->last_purge_at = std::chrono::system_clock::now();
        }
        return purged;
    } catch (const std::exception& ex) {
        if (diagnostics_)
            diagnostics_->log_event(FilesDiagnosticCategory::Purge, "purge_failed", {}, ex.what());
        return 0;
    } catch (...) {
        return 0;
    }
}

void FilesOutboxRelay::drain_on_shutdown() {
    if (config_.shutdown_drain_timeout.count() <= 0) {
        return;
    }

    const auto deadline = std::chrono::steady_clock::now() + config_.shutdown_drain_timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (consecutive_failures_.load(std::memory_order_relaxed) > 0) {
            break;
        }
        const size_t processed = poll_and_dispatch(config_.batch_size);
        if (processed == 0) {
            break;
        }
    }
}

void FilesOutboxRelay::record_success_diag() {
    if (!diagnostics_) {
        return;
    }
    const bool recovered = consecutive_failures_.load(std::memory_order_relaxed) > 0;
    std::lock_guard<std::mutex> lock(diagnostics_->mutex);
    diagnostics_->last_status_code = static_cast<int>(grpc::StatusCode::OK);
    diagnostics_->last_error_message.clear();
    diagnostics_->consecutive_failures = 0;
    diagnostics_->last_success_at = std::chrono::system_clock::now();
    if (recovered)
        diagnostics_->log_event(FilesDiagnosticCategory::Recovery, "audit_recovered");
}

void FilesOutboxRelay::record_failure_diag(grpc::StatusCode code, const std::string& message) {
    if (!diagnostics_) {
        return;
    }
    std::lock_guard<std::mutex> lock(diagnostics_->mutex);
    diagnostics_->last_status_code = static_cast<int>(code);
    diagnostics_->last_error_message = message;
    diagnostics_->consecutive_failures = consecutive_failures_.load(std::memory_order_relaxed);
    diagnostics_->last_failure_at = std::chrono::system_clock::now();
    diagnostics_->log_event(FilesDiagnosticCategory::Outage, "audit_unavailable", {}, message,
                            static_cast<uint64_t>(code));
}

void FilesOutboxRelay::run() {
    auto next_purge = std::chrono::steady_clock::now() + config_.purge_interval;

    while (running_.load()) {
        notified_.store(false, std::memory_order_release);

        try {
            const size_t processed = poll_and_dispatch(config_.batch_size);

            if (std::chrono::steady_clock::now() >= next_purge) {
                purge_old_published_records();
                next_purge = std::chrono::steady_clock::now() + config_.purge_interval;
            }

            if (!running_.load()) {
                break;
            }

            const uint32_t failures = consecutive_failures_.load(std::memory_order_relaxed);
            if (failures > 0) {
                const auto backoff = compute_backoff_delay(failures);
                std::unique_lock<std::mutex> lock(cv_mutex_);
                cv_.wait_for(lock, backoff, [this]() { return !running_.load(); });
            } else if (processed == 0 && !notified_.load(std::memory_order_acquire)) {
                std::unique_lock<std::mutex> lock(cv_mutex_);
                cv_.wait_for(lock, config_.poll_interval,
                             [this]() { return !running_.load() || notified_.load(std::memory_order_acquire); });
            }
        } catch (const std::exception& ex) {
            if (diagnostics_)
                diagnostics_->log_event(FilesDiagnosticCategory::Lease, "worker_failed", {}, ex.what());
            if (running_.load()) {
                std::unique_lock<std::mutex> lock(cv_mutex_);
                cv_.wait_for(lock, config_.poll_interval, [this]() { return !running_.load(); });
            }
        } catch (...) {
            if (diagnostics_)
                diagnostics_->log_event(FilesDiagnosticCategory::Lease, "worker_failed", {}, "unknown exception");
            if (running_.load()) {
                std::unique_lock<std::mutex> lock(cv_mutex_);
                cv_.wait_for(lock, config_.poll_interval, [this]() { return !running_.load(); });
            }
        }
    }

    if (stopping_.load()) {
        drain_on_shutdown();
    }
}

} // namespace securecloud::files::audit
