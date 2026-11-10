#pragma once

#include "audit_pending_store.hpp"
#include "crc32c.hpp"
#include "gateway_audit_spool_config.hpp"

#include <atomic>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace securecloud::gateway::audit {

/**
 * @brief Thread-safe segmented WAL file spool with group-commit fsync (Option B).
 *
 * Guarantees `append()` never blocks on disk I/O. Uses dedicated background writer
 * thread and crash-safe segment index recovery.
 */
class FileSpoolPendingStore final : public IAuditPendingStore {
  public:
    explicit FileSpoolPendingStore(GatewayAuditSpoolConfig config);
    ~FileSpoolPendingStore() override;

    [[nodiscard]] StoreDurability durability() const noexcept override { return StoreDurability::DurableAfterSync; }

    [[nodiscard]] AdmissionResult append(PendingRecord record) noexcept override;

    [[nodiscard]] std::vector<PendingRecord> claim_batch(size_t max_records) override;

    void mark_delivered(std::span<const securecloud::audit::domain::EventId> event_ids) override;

    void mark_terminal(const securecloud::audit::domain::EventId& event_id, TerminalReason reason) override;

    void release(std::span<const securecloud::audit::domain::EventId> event_ids) override;

    [[nodiscard]] PendingStats stats() const noexcept override;

    [[nodiscard]] bool is_available() const noexcept { return available_.load(std::memory_order_relaxed); }

  private:
    void init_spool();
    void recover_and_rebuild_index();
    void writer_thread_loop();
    void perform_group_commit();

    GatewayAuditSpoolConfig config_;
    std::atomic<bool> available_{false};
    std::atomic<bool> running_{true};

    mutable std::mutex mutex_;
    std::condition_variable cv_;

    std::deque<PendingRecord> handoff_queue_;

    std::unordered_map<securecloud::audit::domain::EventId, PendingRecord> pending_map_;
    std::deque<securecloud::audit::domain::EventId> pending_order_;
    std::unordered_map<securecloud::audit::domain::EventId, PendingRecord> claimed_map_;
    std::unordered_set<securecloud::audit::domain::EventId> delivered_set_;

    size_t total_spool_bytes_{0};
    uint64_t dropped_count_{0};
    uint64_t unrecoverable_count_{0};

    std::thread writer_thread_;
};

} // namespace securecloud::gateway::audit
