#pragma once

#include "files/audit/audit_client_interface.hpp"
#include "files/audit/files_audit_mapper.hpp"
#include "files/files_config.hpp"
#include "files/repository/files_outbox_repository.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

namespace securecloud::files::audit {

using FilesOutboxRelayConfig = ::securecloud::files::FilesOutboxRelayConfig;

struct FilesOutboxMetrics {
    std::atomic<uint64_t> batches_dispatched{0};
    std::atomic<uint64_t> events_published{0};
    std::atomic<uint64_t> events_quarantined{0};
    std::atomic<uint64_t> transient_failures{0};
    std::atomic<uint64_t> security_auth_failures{0};
    std::atomic<uint64_t> rows_purged{0};
};

struct FilesOutboxDiagnostics {
    std::mutex mutex;
    std::string last_error_message;
    grpc::StatusCode last_status_code{grpc::StatusCode::OK};
    uint32_t consecutive_failures{0};
    std::chrono::system_clock::time_point last_success_at{};
    std::chrono::system_clock::time_point last_failure_at{};
    std::chrono::system_clock::time_point last_purge_at{};
};

/**
 * @brief Transactional outbox background relay worker for Files Service.
 *
 * Continuously polls `files_outbox`, maps and pre-flight validates events locally
 * (failing corrupted rows fast into QUARANTINED), dispatches valid batches via
 * IFilesAuditClient, and transitions rows to PUBLISHED / PENDING (transient) / QUARANTINED.
 */
class FilesOutboxRelay {
  public:
    FilesOutboxRelay(std::shared_ptr<IFilesOutboxRepository> outbox_repo,
                     std::shared_ptr<IFilesAuditClient> audit_client, FilesOutboxRelayConfig config = {},
                     std::string producer_instance = "files-1", FilesOutboxMetrics* metrics = nullptr,
                     FilesOutboxDiagnostics* diagnostics = nullptr);
    ~FilesOutboxRelay();

    FilesOutboxRelay(const FilesOutboxRelay&) = delete;
    FilesOutboxRelay& operator=(const FilesOutboxRelay&) = delete;
    FilesOutboxRelay(FilesOutboxRelay&&) = delete;
    FilesOutboxRelay& operator=(FilesOutboxRelay&&) = delete;

    void start();
    void stop();
    void notify() noexcept;
    [[nodiscard]] bool is_running() const noexcept;

    /// Synchronously polls, pre-flight validates, and dispatches a single batch of events.
    /// Returns the number of outbox rows processed (quarantined locally or dispatched).
    size_t poll_and_dispatch(size_t batch_size);

    size_t purge_old_published_records();

    [[nodiscard]] std::chrono::milliseconds compute_backoff_delay(uint32_t failure_attempt) const;

  private:
    void run();
    void drain_on_shutdown();
    void dispatch_chunk(const std::vector<FilesOutboxEntity>& chunk_events,
                        const std::vector<securecloud::audit::v1::AuditEventProto>& chunk_protos);
    void probe_and_isolate_invalid_batch(const std::vector<FilesOutboxEntity>& chunk_events,
                                         const std::vector<securecloud::audit::v1::AuditEventProto>& chunk_protos);
    void record_success_diag();
    void record_failure_diag(grpc::StatusCode code, const std::string& message);

    std::shared_ptr<IFilesOutboxRepository> outbox_repo_;
    std::shared_ptr<IFilesAuditClient> audit_client_;
    FilesOutboxRelayConfig config_;
    std::string producer_instance_;
    FilesOutboxMetrics* metrics_{nullptr};
    FilesOutboxDiagnostics* diagnostics_{nullptr};

    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};
    std::atomic<bool> notified_{false};
    std::atomic<uint32_t> consecutive_failures_{0};

    std::thread worker_thread_;
    std::mutex cv_mutex_;
    std::condition_variable cv_;
    mutable std::mutex rng_mutex_;
    mutable std::mt19937 rng_;
};

} // namespace securecloud::files::audit
