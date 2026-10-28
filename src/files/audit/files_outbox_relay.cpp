#include "files/audit/files_outbox_relay.hpp"

#include <iostream>
#include <utility>

namespace securecloud::files::audit {

FilesOutboxRelay::FilesOutboxRelay(std::shared_ptr<FilesOutboxRepository> outbox_repo,
                                   std::shared_ptr<IFilesAuditClient> audit_client,
                                   FilesOutboxRelayConfig config)
    : outbox_repo_(std::move(outbox_repo)),
      audit_client_(std::move(audit_client)),
      config_(config) {}

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

    std::vector<securecloud::audit::v1::AuditEventProto> proto_batch;
    proto_batch.reserve(events.size());
    for (const auto& ev : events) {
        proto_batch.push_back(FilesAuditMapper::to_proto(ev));
    }

    bool success = false;
    try {
        success = audit_client_->submit_batch(proto_batch);
    } catch (const std::exception& ex) {
        std::cerr << "[SecureCloud] [files-outbox-relay] Exception submitting batch to audit: " << ex.what() << "\n";
        success = false;
    } catch (...) {
        std::cerr << "[SecureCloud] [files-outbox-relay] Unknown error submitting batch to audit\n";
        success = false;
    }

    for (const auto& ev : events) {
        try {
            if (success) {
                outbox_repo_->mark_published(ev.event_id);
            } else {
                outbox_repo_->mark_failed(ev.event_id);
            }
        } catch (const std::exception& ex) {
            std::cerr << "[SecureCloud] [files-outbox-relay] Failed to update event " << ev.event_id
                      << " state: " << ex.what() << "\n";
        } catch (...) {
            // Ignore
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
                cv_.wait_for(lock, config_.poll_interval_ms, [this]() {
                    return !running_.load();
                });
            }
        } catch (const std::exception& ex) {
            std::cerr << "[SecureCloud] [files-outbox-relay] Worker thread error: " << ex.what() << "\n";
            if (running_.load()) {
                std::unique_lock<std::mutex> lock(cv_mutex_);
                cv_.wait_for(lock, config_.poll_interval_ms, [this]() {
                    return !running_.load();
                });
            }
        } catch (...) {
            std::cerr << "[SecureCloud] [files-outbox-relay] Unknown worker thread error\n";
            if (running_.load()) {
                std::unique_lock<std::mutex> lock(cv_mutex_);
                cv_.wait_for(lock, config_.poll_interval_ms, [this]() {
                    return !running_.load();
                });
            }
        }
    }
}

} // namespace securecloud::files::audit
