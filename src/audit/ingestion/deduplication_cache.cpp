#include "ingestion/deduplication_cache.hpp"

#include "ingestion/deduplication_metrics.hpp"

#include <algorithm>
#include <bit>

namespace securecloud::audit::ingestion {

BoundedDeduplicationCache::BoundedDeduplicationCache(uint32_t capacity, std::chrono::milliseconds ttl,
                                                     uint32_t num_shards)
    : total_capacity_(capacity == 0 ? 1u : capacity), ttl_(ttl) {
    if (num_shards == 0)
        num_shards = 1;
    num_shards_ = std::bit_ceil(num_shards);
    shard_mask_ = num_shards_ - 1;
    shard_capacity_ = std::max(1u, (total_capacity_ + num_shards_ - 1) / num_shards_);

    shards_.reserve(num_shards_);
    for (uint32_t i = 0; i < num_shards_; ++i) {
        shards_.push_back(std::make_unique<CacheShard>());
    }
}

size_t BoundedDeduplicationCache::get_shard_index(const domain::EventId& event_id) const noexcept {
    return std::hash<domain::EventId>{}(event_id)&shard_mask_;
}

DedupAcquireResult BoundedDeduplicationCache::try_acquire(const domain::EventId& event_id,
                                                          const domain::EventPayloadFingerprint& fingerprint,
                                                          std::chrono::steady_clock::time_point now) {
    auto& shard = *shards_[get_shard_index(event_id)];
    std::lock_guard<std::mutex> lock(shard.mutex);

    // 1. Inspect committed_map
    auto committed_it = shard.committed_map.find(event_id);
    if (committed_it != shard.committed_map.end()) {
        auto lru_it = committed_it->second;
        if (now >= lru_it->expires_at) {
            // Lazy eviction of TTL-expired entry
            shard.committed_lru_list.erase(lru_it);
            shard.committed_map.erase(committed_it);
            DeduplicationMetrics::instance().audit_dedup_cache_evictions_ttl_total.fetch_add(1,
                                                                                             std::memory_order_relaxed);
        } else {
            if (lru_it->fingerprint != fingerprint) {
                DeduplicationMetrics::instance().audit_dedup_payload_conflicts_total.fetch_add(
                    1, std::memory_order_relaxed);
                return DedupAcquireResult{.decision = DedupAcquireResult::Decision::PayloadConflict};
            }
            // LRU promotion
            shard.committed_lru_list.splice(shard.committed_lru_list.begin(), shard.committed_lru_list, lru_it);
            DeduplicationMetrics::instance().audit_dedup_hits_committed_total.fetch_add(1, std::memory_order_relaxed);
            return DedupAcquireResult{.decision = DedupAcquireResult::Decision::AlreadyCommitted,
                                      .committed_received_at = lru_it->committed_received_at,
                                      .in_flight_future = {},
                                      .primary_promise = nullptr};
        }
    }

    // 2. Inspect in_flight_map
    auto in_flight_it = shard.in_flight_map.find(event_id);
    if (in_flight_it != shard.in_flight_map.end()) {
        if (in_flight_it->second.fingerprint != fingerprint) {
            DeduplicationMetrics::instance().audit_dedup_payload_conflicts_total.fetch_add(1,
                                                                                           std::memory_order_relaxed);
            return DedupAcquireResult{.decision = DedupAcquireResult::Decision::PayloadConflict};
        }
        DeduplicationMetrics::instance().audit_dedup_hits_inflight_coalesced_total.fetch_add(1,
                                                                                             std::memory_order_relaxed);
        return DedupAcquireResult{.decision = DedupAcquireResult::Decision::CoalescedInFlight,
                                  .committed_received_at = {},
                                  .in_flight_future = in_flight_it->second.in_flight_future,
                                  .primary_promise = nullptr};
    }

    // 3. State is UNSEEN: allocate primary promise and shared_future
    auto promise = std::make_shared<std::promise<PersistAckResult>>();
    std::shared_future<PersistAckResult> future = promise->get_future().share();

    InFlightEntry entry{.fingerprint = fingerprint, .primary_promise = promise, .in_flight_future = future};

    shard.in_flight_map.emplace(event_id, entry);

    return DedupAcquireResult{.decision = DedupAcquireResult::Decision::AcquiredNewInFlight,
                              .committed_received_at = {},
                              .in_flight_future = future,
                              .primary_promise = promise};
}

void BoundedDeduplicationCache::mark_committed(const domain::EventId& event_id,
                                               std::chrono::system_clock::time_point received_at,
                                               std::chrono::steady_clock::time_point now) {
    auto& shard = *shards_[get_shard_index(event_id)];
    std::shared_ptr<std::promise<PersistAckResult>> promise_to_fulfill;

    {
        std::lock_guard<std::mutex> lock(shard.mutex);
        auto in_flight_it = shard.in_flight_map.find(event_id);
        if (in_flight_it == shard.in_flight_map.end()) {
            return;
        }

        domain::EventPayloadFingerprint fp = in_flight_it->second.fingerprint;
        promise_to_fulfill = in_flight_it->second.primary_promise;

        shard.in_flight_map.erase(in_flight_it);

        auto c_it = shard.committed_map.find(event_id);
        if (c_it != shard.committed_map.end()) {
            shard.committed_lru_list.erase(c_it->second);
            shard.committed_map.erase(c_it);
        }

        CommittedEntry committed_entry{
            .event_id = event_id, .fingerprint = fp, .committed_received_at = received_at, .expires_at = now + ttl_};

        shard.committed_lru_list.push_front(committed_entry);
        shard.committed_map[event_id] = shard.committed_lru_list.begin();

        DeduplicationMetrics::instance().audit_events_persisted_new_total.fetch_add(1, std::memory_order_relaxed);

        // Apply LRU eviction ceiling when committed_map exceeds shard capacity
        while (shard.committed_map.size() > shard_capacity_) {
            if (!shard.committed_lru_list.empty()) {
                auto tail_it = std::prev(shard.committed_lru_list.end());
                shard.committed_map.erase(tail_it->event_id);
                shard.committed_lru_list.pop_back();
                DeduplicationMetrics::instance().audit_dedup_cache_evictions_lru_total.fetch_add(
                    1, std::memory_order_relaxed);
            } else {
                break;
            }
        }
    }

    if (promise_to_fulfill) {
        PersistAckResult ack{.status = IngestionOutcomeStatus::DuplicateCoalesced,
                             .event_id = event_id,
                             .received_at = received_at,
                             .error_code = "",
                             .diagnostic_message = ""};
        try {
            promise_to_fulfill->set_value(ack);
        } catch (...) {
            // Safe guard against duplicate fulfillment
        }
    }
}

void BoundedDeduplicationCache::rollback_in_flight(const domain::EventId& event_id,
                                                   const PersistAckResult& failure_result) {
    auto& shard = *shards_[get_shard_index(event_id)];
    std::shared_ptr<std::promise<PersistAckResult>> promise_to_fulfill;

    {
        std::lock_guard<std::mutex> lock(shard.mutex);
        auto in_flight_it = shard.in_flight_map.find(event_id);
        if (in_flight_it == shard.in_flight_map.end()) {
            return;
        }

        promise_to_fulfill = in_flight_it->second.primary_promise;
        shard.in_flight_map.erase(in_flight_it);
        DeduplicationMetrics::instance().audit_dedup_inflight_rollbacks_total.fetch_add(1, std::memory_order_relaxed);
    }

    if (promise_to_fulfill) {
        try {
            promise_to_fulfill->set_value(failure_result);
        } catch (...) {
            // Safe guard against duplicate fulfillment
        }
    }
}

size_t BoundedDeduplicationCache::evict_expired(std::chrono::steady_clock::time_point now) {
    size_t total_evicted = 0;
    for (const auto& shard : shards_) {
        std::lock_guard<std::mutex> lock(shard->mutex);
        auto it = shard->committed_lru_list.begin();
        while (it != shard->committed_lru_list.end()) {
            if (now >= it->expires_at) {
                shard->committed_map.erase(it->event_id);
                it = shard->committed_lru_list.erase(it);
                ++total_evicted;
                DeduplicationMetrics::instance().audit_dedup_cache_evictions_ttl_total.fetch_add(
                    1, std::memory_order_relaxed);
            } else {
                ++it;
            }
        }
    }
    return total_evicted;
}

size_t BoundedDeduplicationCache::size() const noexcept {
    size_t total = 0;
    for (const auto& shard : shards_) {
        std::lock_guard<std::mutex> lock(shard->mutex);
        total += shard->in_flight_map.size() + shard->committed_map.size();
    }
    return total;
}

size_t BoundedDeduplicationCache::in_flight_count() const noexcept {
    size_t total = 0;
    for (const auto& shard : shards_) {
        std::lock_guard<std::mutex> lock(shard->mutex);
        total += shard->in_flight_map.size();
    }
    return total;
}

size_t BoundedDeduplicationCache::committed_count() const noexcept {
    size_t total = 0;
    for (const auto& shard : shards_) {
        std::lock_guard<std::mutex> lock(shard->mutex);
        total += shard->committed_map.size();
    }
    return total;
}

} // namespace securecloud::audit::ingestion