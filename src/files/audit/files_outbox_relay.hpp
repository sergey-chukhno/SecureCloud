#pragma once

#include "files/audit/audit_client_interface.hpp"
#include "files/audit/files_audit_mapper.hpp"
#include "files/repository/files_outbox_repository.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>

namespace securecloud::files::audit {

struct FilesOutboxRelayConfig {
    std::chrono::milliseconds poll_interval_ms{1000};
    size_t batch_size{50};
    uint32_t max_retries{5};
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
                     std::shared_ptr<IFilesAuditClient> audit_client, FilesOutboxRelayConfig config = {});
    ~FilesOutboxRelay();

    FilesOutboxRelay(const FilesOutboxRelay&) = delete;
    FilesOutboxRelay& operator=(const FilesOutboxRelay&) = delete;
    FilesOutboxRelay(FilesOutboxRelay&&) = delete;
    FilesOutboxRelay& operator=(FilesOutboxRelay&&) = delete;

    void start();
    void stop();
    [[nodiscard]] bool is_running() const noexcept;

    /// Synchronously polls, pre-flight validates, and dispatches a single batch of events.
    /// Returns the number of outbox rows processed (quarantined locally or dispatched).
    size_t poll_and_dispatch(size_t batch_size);

  private:
    void run();

    std::shared_ptr<IFilesOutboxRepository> outbox_repo_;
    std::shared_ptr<IFilesAuditClient> audit_client_;
    FilesOutboxRelayConfig config_;

    std::atomic<bool> running_{false};
    std::thread worker_thread_;
    std::mutex cv_mutex_;
    std::condition_variable cv_;
};

} // namespace securecloud::files::audit
