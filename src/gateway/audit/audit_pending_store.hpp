#pragma once

#include "domain/event_id.hpp"
#include "gateway_audit_event_types.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace securecloud::gateway::audit {

enum class StoreDurability : uint8_t {
    NonDurable,      // Pure in-memory queue (lost on process restart)
    DurableAfterSync // Durable file spool backed by group-commit fsync (ADR-011)
};

enum class AdmissionResult : uint8_t {
    DurablyQueued,       // Written and group-commit fsync'd to disk WAL
    AcceptedPendingSync, // Accepted into non-blocking writer queue pending fsync
    AcceptedNonDurable,  // Accepted into bounded in-memory buffer
    RejectedFull,        // Store capacity limit reached
    RejectedUnavailable, // Disk spool directory unwritable / I/O failure
    RejectedInvalid      // Format or validation failure
};

enum class TerminalReason : uint8_t { ValidationFailed, FormatCorrupted, MaxRetriesExceeded };

struct PendingRecord {
    securecloud::audit::domain::EventId event_id{};
    AuditEventClass durability_class{AuditEventClass::Mandatory};
    std::vector<uint8_t> proto_bytes{};
    std::chrono::system_clock::time_point enqueued_at{std::chrono::system_clock::now()};
    uint32_t attempt_count{0};
};

struct PendingStats {
    size_t total_records{0};
    size_t total_bytes{0};
    size_t claimed_records{0};
    uint64_t dropped_records{0};
    uint64_t unrecoverable_records{0};
};

/**
 * @brief Thread-safe interface for Gateway pending audit event persistence.
 */
class IAuditPendingStore {
  public:
    virtual ~IAuditPendingStore() = default;

    [[nodiscard]] virtual StoreDurability durability() const noexcept = 0;

    /// Non-blocking event admission into the store
    [[nodiscard]] virtual AdmissionResult append(PendingRecord record) noexcept = 0;

    /// Claims a batch of unacknowledged records for upstream delivery
    [[nodiscard]] virtual std::vector<PendingRecord> claim_batch(size_t max_records) = 0;

    /// Marks records as successfully ingested by upstream Audit Service
    virtual void mark_delivered(std::span<const securecloud::audit::domain::EventId> event_ids) = 0;

    /// Marks a record as permanently unrecoverable (quarantines record)
    virtual void mark_terminal(const securecloud::audit::domain::EventId& event_id, TerminalReason reason) = 0;

    /// Releases claimed records back to pending queue for retry
    virtual void release(std::span<const securecloud::audit::domain::EventId> event_ids) = 0;

    [[nodiscard]] virtual PendingStats stats() const noexcept = 0;
};

} // namespace securecloud::gateway::audit
