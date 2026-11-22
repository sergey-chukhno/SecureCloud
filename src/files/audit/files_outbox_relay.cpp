#include "files/audit/files_outbox_relay.hpp"

#include "files/audit/grpc_audit_client.hpp"

#include <algorithm>
#include <iostream>
#include <unordered_set>
#include <utility>
#include <vector>

namespace securecloud::files::audit {

FilesOutboxRelay::FilesOutboxRelay(std::shared_ptr<IFilesOutboxRepository> outbox_repo,
                                   std::shared_ptr<IFilesAuditClient> audit_client, FilesOutboxRelayConfig config)
    : outbox_repo_(std::move(outbox_repo)), audit_client_(std::move(audit_client)), config_(config) {}

FilesOutboxRelay::~FilesOutboxRelay() {
    stop();
}

void FilesOutboxRelay::start() {
    if (running_.exchange(true)) {
        return;
    }
    worker_thread_ = std::thread(&FilesOutboxRelay::run, this);
}

void FilesOutboxRelay::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    cv_.notify_all();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

bool FilesOutboxRelay::is_running() const noexcept {
    return running_.load();
}

size_t FilesOutboxRelay::poll_and_dispatch(size_t batch_size) {
    if (!outbox_repo_ || !audit_client_ || batch_size == 0) {
        return 0;
    }

    std::vector<FilesOutboxEntity> events;
    try {
        events = outbox_repo_->fetch_pending_events(batch_size);
    } catch (const std::exception& ex) {
        std::cerr << "[SecureCloud] [files-outbox-relay] Error fetching pending events: " << ex.what() << "\n";
        return 0;
    } catch (...) {
        std::cerr << "[SecureCloud] [files-outbox-relay] Unknown error fetching pending events\n";
        return 0;
    }

    if (events.empty()) {
        return 0;
    }

    std::vector<FilesOutboxEntity> valid_events;
    std::vector<securecloud::audit::v1::AuditEventProto> valid_protos;
    valid_events.reserve(events.size());
    valid_protos.reserve(events.size());

    const auto now = std::chrono::system_clock::now();
    for (const auto& ev : events) {
        auto mapped = FilesAuditMapper::to_validated_proto(ev, now);
        if (!mapped.valid) {
            try {
                outbox_repo_->mark_quarantined(ev.event_id, "local_validation_failed: " + mapped.validation_error);
            } catch (const std::exception& ex) {
                std::cerr << "[SecureCloud] [files-outbox-relay] Failed to quarantine invalid event " << ev.event_id
                          << ": " << ex.what() << "\n";
            } catch (...) {
                // Ignore
            }
            continue;
        }
        valid_events.push_back(ev);
        valid_protos.push_back(std::move(mapped.proto));
    }

    if (valid_protos.empty()) {
        return events.size();
    }

    // Dispatch in bounded chunks <= GrpcAuditClient::k_max_batch_size (100)
    constexpr size_t k_max_chunk = GrpcAuditClient::k_max_batch_size;
    for (size_t offset = 0; offset < valid_protos.size(); offset += k_max_chunk) {
        const size_t count = std::min(k_max_chunk, valid_protos.size() - offset);
        std::vector<securecloud::audit::v1::AuditEventProto> chunk_protos(
            valid_protos.begin() + static_cast<std::ptrdiff_t>(offset),
            valid_protos.begin() + static_cast<std::ptrdiff_t>(offset + count));

        FilesAuditBatchSubmitResult submit_result;
        try {
            submit_result = audit_client_->submit_batch(chunk_protos);
        } catch (const std::exception& ex) {
            std::cerr << "[SecureCloud] [files-outbox-relay] Exception submitting batch to audit: " << ex.what()
                      << "\n";
            submit_result.rpc_success = false;
            submit_result.status = grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
        } catch (...) {
            std::cerr << "[SecureCloud] [files-outbox-relay] Unknown error submitting batch to audit\n";
            submit_result.rpc_success = false;
            submit_result.status = grpc::Status(grpc::StatusCode::UNKNOWN, "unknown_submit_exception");
        }

        if (!submit_result.rpc_success) {
            const std::string err_msg = submit_result.status.error_message().empty()
                                            ? "audit_rpc_failed"
                                            : submit_result.status.error_message();
            for (size_t i = 0; i < count; ++i) {
                const auto& ev = valid_events[offset + i];
                try {
                    outbox_repo_->record_transient_failure(ev.event_id, err_msg);
                } catch (const std::exception& ex) {
                    std::cerr << "[SecureCloud] [files-outbox-relay] Failed to record transient failure for event "
                              << ev.event_id << ": " << ex.what() << "\n";
                } catch (...) {
                    // Ignore
                }
            }
            continue;
        }

        std::unordered_set<std::string> rejected_ids(submit_result.rejected_event_ids.begin(),
                                                     submit_result.rejected_event_ids.end());

        for (size_t i = 0; i < count; ++i) {
            const auto& ev = valid_events[offset + i];
            try {
                if (rejected_ids.contains(ev.event_id)) {
                    outbox_repo_->mark_quarantined(ev.event_id, "audit_service_rejected");
                } else {
                    outbox_repo_->mark_published(ev.event_id);
                }
            } catch (const std::exception& ex) {
                std::cerr << "[SecureCloud] [files-outbox-relay] Failed to update event " << ev.event_id
                          << " state: " << ex.what() << "\n";
            } catch (...) {
                // Ignore
            }
        }
    }

    return events.size();
}

void FilesOutboxRelay::run() {
    while (running_.load()) {
        try {
            size_t processed = poll_and_dispatch(config_.batch_size);
            if (processed == 0 && running_.load()) {
                std::unique_lock<std::mutex> lock(cv_mutex_);
                cv_.wait_for(lock, config_.poll_interval_ms, [this]() { return !running_.load(); });
            }
        } catch (const std::exception& ex) {
            std::cerr << "[SecureCloud] [files-outbox-relay] Worker thread error: " << ex.what() << "\n";
            if (running_.load()) {
                std::unique_lock<std::mutex> lock(cv_mutex_);
                cv_.wait_for(lock, config_.poll_interval_ms, [this]() { return !running_.load(); });
            }
        } catch (...) {
            std::cerr << "[SecureCloud] [files-outbox-relay] Unknown worker thread error\n";
            if (running_.load()) {
                std::unique_lock<std::mutex> lock(cv_mutex_);
                cv_.wait_for(lock, config_.poll_interval_ms, [this]() { return !running_.load(); });
            }
        }
    }
}

} // namespace securecloud::files::audit
