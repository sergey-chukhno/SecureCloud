#pragma once

#include "audit_pending_store.hpp"

#include <deque>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace securecloud::gateway::audit {

/**
 * @brief Thread-safe, non-blocking in-memory pending store for BestEffort events.
 *
 * Drops oldest best-effort events when capacity is exhausted to maintain memory bounds.
 */
class BoundedMemoryPendingStore final : public IAuditPendingStore {
  public:
    explicit BoundedMemoryPendingStore(size_t max_records = 10000, size_t max_bytes = 10485760);

    [[nodiscard]] StoreDurability durability() const noexcept override { return StoreDurability::NonDurable; }

    [[nodiscard]] AdmissionResult append(PendingRecord record) noexcept override;

    [[nodiscard]] std::vector<PendingRecord> claim_batch(size_t max_records) override;

    void mark_delivered(std::span<const securecloud::audit::domain::EventId> event_ids) override;

    void mark_terminal(const securecloud::audit::domain::EventId& event_id, TerminalReason reason) override;

    void release(std::span<const securecloud::audit::domain::EventId> event_ids) override;

    [[nodiscard]] PendingStats stats() const noexcept override;

  private:
    const size_t max_records_;
    const size_t max_bytes_;

    mutable std::mutex mutex_;
    std::deque<PendingRecord> queue_;
    std::unordered_map<securecloud::audit::domain::EventId, PendingRecord> claimed_map_;

    size_t current_bytes_{0};
    uint64_t dropped_records_count_{0};
    uint64_t terminal_records_count_{0};
};

} // namespace securecloud::gateway::audit
