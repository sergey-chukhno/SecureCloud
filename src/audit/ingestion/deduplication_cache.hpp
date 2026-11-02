#pragma once

#include "domain/event_id.hpp"
#include "domain/event_payload_fingerprint.hpp"
#include "ingestion/idempotency_types.hpp"

#include <bit>
#include <chrono>
#include <cstdint>
#include <future>
#include <list>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace securecloud::audit::ingestion {

struct DedupAcquireResult {
    enum class Decision : uint8_t {
        AcquiredNewInFlight = 0, // Caller owns the primary pipeline slot and AckPromise
        CoalescedInFlight = 1,   // Another thread is currently processing identical event; attach to shared_future
        AlreadyCommitted = 2,    // Event already durably persisted with identical fingerprint
        PayloadConflict = 3      // Event exists (InFlight or Committed) with DIFFERENT fingerprint!
    };

    Decision decision{Decision::AcquiredNewInFlight};
    std::chrono::system_clock::time_point committed_received_at{};
    std::shared_future<PersistAckResult> in_flight_future{};
    std::shared_ptr<std::promise<PersistAckResult>> primary_promise{};
};

class IDeduplicationCache {
  public:
    virtual ~IDeduplicationCache() = default;

    /// Atomically inspects or reserves event_id in the cache.
    virtual DedupAcquireResult try_acquire(const domain::EventId& event_id,
                                           const domain::EventPayloadFingerprint& fingerprint,
                                           std::chrono::steady_clock::time_point now) = 0;

    /// Transitions an IN_FLIGHT entry to COMMITTED after ClickHouse confirms durable insert,
    /// starts the 10-minute TTL window, and fulfills the shared AckFuture for any coalesced waiters.
    virtual void mark_committed(const domain::EventId& event_id, std::chrono::system_clock::time_point received_at,
                                std::chrono::steady_clock::time_point now) = 0;

    /// Rolls back and removes an IN_FLIGHT entry when queuing fails, ClickHouse insert fails,
    /// or a timeout produces an ambiguous outcome, notifying coalesced waiters with failure_result.
    virtual void rollback_in_flight(const domain::EventId& event_id, const PersistAckResult& failure_result) = 0;

    /// Evicts expired COMMITTED entries across shards.
    virtual size_t evict_expired(std::chrono::steady_clock::time_point now) = 0;

    [[nodiscard]] virtual size_t size() const noexcept = 0;
    [[nodiscard]] virtual size_t in_flight_count() const noexcept = 0;
    [[nodiscard]] virtual size_t committed_count() const noexcept = 0;
};

class BoundedDeduplicationCache : public IDeduplicationCache {
  public:
    explicit BoundedDeduplicationCache(uint32_t capacity = 100000,
                                       std::chrono::milliseconds ttl = std::chrono::minutes(10),
                                       uint32_t num_shards = 64);

    ~BoundedDeduplicationCache() override = default;

    BoundedDeduplicationCache(const BoundedDeduplicationCache&) = delete;
    BoundedDeduplicationCache& operator=(const BoundedDeduplicationCache&) = delete;

    DedupAcquireResult try_acquire(const domain::EventId& event_id, const domain::EventPayloadFingerprint& fingerprint,
                                   std::chrono::steady_clock::time_point now) override;

    void mark_committed(const domain::EventId& event_id, std::chrono::system_clock::time_point received_at,
                        std::chrono::steady_clock::time_point now) override;

    void rollback_in_flight(const domain::EventId& event_id, const PersistAckResult& failure_result) override;

    size_t evict_expired(std::chrono::steady_clock::time_point now) override;

    [[nodiscard]] size_t size() const noexcept override;
    [[nodiscard]] size_t in_flight_count() const noexcept override;
    [[nodiscard]] size_t committed_count() const noexcept override;

  private:
    struct InFlightEntry {
        domain::EventPayloadFingerprint fingerprint;
        std::shared_ptr<std::promise<PersistAckResult>> primary_promise;
        std::shared_future<PersistAckResult> in_flight_future;
    };

    struct CommittedEntry {
        domain::EventId event_id;
        domain::EventPayloadFingerprint fingerprint;
        std::chrono::system_clock::time_point committed_received_at;
        std::chrono::steady_clock::time_point expires_at;
    };

    struct CacheShard {
        mutable std::mutex mutex;
        std::unordered_map<domain::EventId, InFlightEntry> in_flight_map;
        std::list<CommittedEntry> committed_lru_list;
        std::unordered_map<domain::EventId, std::list<CommittedEntry>::iterator> committed_map;
    };

    [[nodiscard]] size_t get_shard_index(const domain::EventId& event_id) const noexcept;

    uint32_t total_capacity_;
    uint32_t shard_capacity_;
    std::chrono::milliseconds ttl_;
    uint32_t num_shards_;
    uint32_t shard_mask_;
    std::vector<std::unique_ptr<CacheShard>> shards_;
};

} // namespace securecloud::audit::ingestion