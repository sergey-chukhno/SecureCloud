#include "bounded_memory_pending_store.hpp"

#include <algorithm>

namespace securecloud::gateway::audit {

BoundedMemoryPendingStore::BoundedMemoryPendingStore(size_t max_records, size_t max_bytes)
    : max_records_(max_records), max_bytes_(max_bytes) {}

AdmissionResult BoundedMemoryPendingStore::append(PendingRecord record) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);

    const size_t record_size = record.proto_bytes.size() + sizeof(PendingRecord);

    // Evict oldest best-effort records if limits exceeded
    while ((queue_.size() >= max_records_ || (current_bytes_ + record_size > max_bytes_)) && !queue_.empty()) {
        const auto& evicted = queue_.front();
        current_bytes_ -= (evicted.proto_bytes.size() + sizeof(PendingRecord));
        queue_.pop_front();
        ++dropped_records_count_;
    }

    if (queue_.size() >= max_records_ || (current_bytes_ + record_size > max_bytes_)) {
        return AdmissionResult::RejectedFull;
    }

    current_bytes_ += record_size;
    queue_.push_back(std::move(record));
    return AdmissionResult::AcceptedNonDurable;
}

std::vector<PendingRecord> BoundedMemoryPendingStore::claim_batch(size_t max_records) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<PendingRecord> batch;
    batch.reserve(std::min(max_records, queue_.size()));

    size_t count = 0;
    while (!queue_.empty() && count < max_records) {
        auto record = std::move(queue_.front());
        queue_.pop_front();

        const size_t record_size = record.proto_bytes.size() + sizeof(PendingRecord);
        current_bytes_ -= record_size;

        record.attempt_count++;
        claimed_map_.emplace(record.event_id, record);
        batch.push_back(std::move(record));
        ++count;
    }

    return batch;
}

void BoundedMemoryPendingStore::mark_delivered(std::span<const securecloud::audit::domain::EventId> event_ids) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& id : event_ids) {
        claimed_map_.erase(id);
    }
}

void BoundedMemoryPendingStore::mark_terminal(const securecloud::audit::domain::EventId& event_id,
                                              TerminalReason /*reason*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (claimed_map_.erase(event_id) > 0) {
        ++terminal_records_count_;
    }
}

void BoundedMemoryPendingStore::release(std::span<const securecloud::audit::domain::EventId> event_ids) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& id : event_ids) {
        auto it = claimed_map_.find(id);
        if (it != claimed_map_.end()) {
            const size_t record_size = it->second.proto_bytes.size() + sizeof(PendingRecord);
            current_bytes_ += record_size;
            queue_.push_front(std::move(it->second));
            claimed_map_.erase(it);
        }
    }
}

PendingStats BoundedMemoryPendingStore::stats() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    PendingStats s;
    s.total_records = queue_.size() + claimed_map_.size();
    s.total_bytes = current_bytes_;
    s.claimed_records = claimed_map_.size();
    s.dropped_records = dropped_records_count_;
    s.unrecoverable_records = terminal_records_count_;
    return s;
}

} // namespace securecloud::gateway::audit
