#include "ingestion/deduplication_cache.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::ingestion::testing {

class BoundedDeduplicationCacheTestSuite : public ::testing::Test {
  protected:
    domain::AuditEvent build_sample_event(const std::string& uuid_str, const std::string& actor = "user_1") {
        domain::AuditEvent event;
        event.event_id = domain::EventId::from_string(uuid_str).value();
        event.occurred_at = std::chrono::system_clock::now();
        event.event_type = "user.login";
        event.severity = domain::Severity::Info;
        event.producer_service = domain::ProducerService::Auth;
        event.producer_instance = "auth-01";
        event.actor_type = domain::ActorType::User;
        event.actor_id = actor;
        event.target_type = domain::TargetType::Service;
        event.target_id = "sys-01";
        event.correlation_id = "corr-123";
        return event;
    }

    std::string make_uuid_string(uint32_t index) {
        char buf[37];
        std::snprintf(buf, sizeof(buf), "018f6e4a-7b3c-7000-8000-%012x", index);
        return std::string(buf);
    }
};

TEST_F(BoundedDeduplicationCacheTestSuite, UnseenToInFlightToCommittedLifecycle) {
    BoundedDeduplicationCache cache(100, std::chrono::minutes(10), 4);
    auto now = std::chrono::steady_clock::now();

    auto event = build_sample_event(make_uuid_string(1));
    auto fp = domain::EventPayloadFingerprint::compute(event);

    // 1. UNSEEN -> IN_FLIGHT
    auto acq1 = cache.try_acquire(event.event_id, fp, now);
    EXPECT_EQ(acq1.decision, DedupAcquireResult::Decision::AcquiredNewInFlight);
    EXPECT_EQ(cache.in_flight_count(), 1u);
    EXPECT_EQ(cache.committed_count(), 0u);

    // 2. IN_FLIGHT -> COMMITTED
    auto received_at = std::chrono::system_clock::now();
    cache.mark_committed(event.event_id, received_at, now);

    EXPECT_EQ(cache.in_flight_count(), 0u);
    EXPECT_EQ(cache.committed_count(), 1u);

    // 3. Subsequent acquire -> AlreadyCommitted
    auto acq2 = cache.try_acquire(event.event_id, fp, now);
    EXPECT_EQ(acq2.decision, DedupAcquireResult::Decision::AlreadyCommitted);
    EXPECT_EQ(acq2.committed_received_at, received_at);
}

TEST_F(BoundedDeduplicationCacheTestSuite, PayloadConflictRejectedWhileInFlightAndWhenCommitted) {
    BoundedDeduplicationCache cache(100, std::chrono::minutes(10), 4);
    auto now = std::chrono::steady_clock::now();

    auto event_orig = build_sample_event(make_uuid_string(2), "user_orig");
    auto fp_orig = domain::EventPayloadFingerprint::compute(event_orig);

    auto event_mod = build_sample_event(make_uuid_string(2), "user_modified");
    auto fp_mod = domain::EventPayloadFingerprint::compute(event_mod);

    // Acquire IN_FLIGHT for original
    auto acq1 = cache.try_acquire(event_orig.event_id, fp_orig, now);
    EXPECT_EQ(acq1.decision, DedupAcquireResult::Decision::AcquiredNewInFlight);

    // Conflict while IN_FLIGHT
    auto acq2 = cache.try_acquire(event_orig.event_id, fp_mod, now);
    EXPECT_EQ(acq2.decision, DedupAcquireResult::Decision::PayloadConflict);

    // Commit original
    auto received_at = std::chrono::system_clock::now();
    cache.mark_committed(event_orig.event_id, received_at, now);

    // Conflict when COMMITTED
    auto acq3 = cache.try_acquire(event_orig.event_id, fp_mod, now);
    EXPECT_EQ(acq3.decision, DedupAcquireResult::Decision::PayloadConflict);

    // Verify original entry remains uncorrupted
    auto acq4 = cache.try_acquire(event_orig.event_id, fp_orig, now);
    EXPECT_EQ(acq4.decision, DedupAcquireResult::Decision::AlreadyCommitted);
}

TEST_F(BoundedDeduplicationCacheTestSuite, TtlExpirationEvictsCommittedEntry) {
    BoundedDeduplicationCache cache(100, std::chrono::minutes(10), 4);
    auto now = std::chrono::steady_clock::now();

    auto event = build_sample_event(make_uuid_string(3));
    auto fp = domain::EventPayloadFingerprint::compute(event);

    cache.try_acquire(event.event_id, fp, now);
    cache.mark_committed(event.event_id, std::chrono::system_clock::now(), now);
    EXPECT_EQ(cache.committed_count(), 1u);

    // Advance time past 10 minutes (600,000 ms)
    auto future_now = now + std::chrono::milliseconds(600001);

    size_t evicted = cache.evict_expired(future_now);
    EXPECT_EQ(evicted, 1u);
    EXPECT_EQ(cache.committed_count(), 0u);

    // Re-acquire after TTL expiration returns AcquiredNewInFlight
    auto acq_after = cache.try_acquire(event.event_id, fp, future_now);
    EXPECT_EQ(acq_after.decision, DedupAcquireResult::Decision::AcquiredNewInFlight);
}

TEST_F(BoundedDeduplicationCacheTestSuite, BoundedCapacity100kLruEviction) {
    const uint32_t capacity = 10;
    BoundedDeduplicationCache cache(capacity, std::chrono::minutes(10), 1);
    auto now = std::chrono::steady_clock::now();

    std::vector<domain::AuditEvent> events;
    for (uint32_t i = 1; i <= capacity; ++i) {
        events.push_back(build_sample_event(make_uuid_string(i)));
        auto fp = domain::EventPayloadFingerprint::compute(events.back());
        cache.try_acquire(events.back().event_id, fp, now);
        cache.mark_committed(events.back().event_id, std::chrono::system_clock::now(), now);
    }

    EXPECT_EQ(cache.committed_count(), capacity);

    // Access entry 1 to promote it in LRU order
    auto fp1 = domain::EventPayloadFingerprint::compute(events[0]);
    cache.try_acquire(events[0].event_id, fp1, now);

    // Insert entry 11 -> causes LRU eviction (entry 2 should be evicted, entry 1 protected)
    auto event_extra = build_sample_event(make_uuid_string(11));
    auto fp_extra = domain::EventPayloadFingerprint::compute(event_extra);
    cache.try_acquire(event_extra.event_id, fp_extra, now);
    cache.mark_committed(event_extra.event_id, std::chrono::system_clock::now(), now);

    EXPECT_LE(cache.committed_count(), capacity);

    // Entry 1 is still present (promoted)
    auto acq1 = cache.try_acquire(events[0].event_id, fp1, now);
    EXPECT_EQ(acq1.decision, DedupAcquireResult::Decision::AlreadyCommitted);

    // Entry 2 was evicted (oldest non-promoted)
    auto fp2 = domain::EventPayloadFingerprint::compute(events[1]);
    auto acq2 = cache.try_acquire(events[1].event_id, fp2, now);
    EXPECT_EQ(acq2.decision, DedupAcquireResult::Decision::AcquiredNewInFlight);
}

TEST_F(BoundedDeduplicationCacheTestSuite, InFlightEntriesPinnedAgainstLruEviction) {
    BoundedDeduplicationCache cache(2, std::chrono::minutes(10), 1);
    auto now = std::chrono::steady_clock::now();

    // 1 IN_FLIGHT entry
    auto event_inflight = build_sample_event(make_uuid_string(100));
    auto fp_inflight = domain::EventPayloadFingerprint::compute(event_inflight);
    cache.try_acquire(event_inflight.event_id, fp_inflight, now);

    // Fill COMMITTED entries past capacity
    for (uint32_t i = 101; i <= 105; ++i) {
        auto e = build_sample_event(make_uuid_string(i));
        auto fp = domain::EventPayloadFingerprint::compute(e);
        cache.try_acquire(e.event_id, fp, now);
        cache.mark_committed(e.event_id, std::chrono::system_clock::now(), now);
    }

    // IN_FLIGHT entry is pinned and was NEVER evicted
    EXPECT_EQ(cache.in_flight_count(), 1u);
    auto acq_inflight = cache.try_acquire(event_inflight.event_id, fp_inflight, now);
    EXPECT_EQ(acq_inflight.decision, DedupAcquireResult::Decision::CoalescedInFlight);
}

TEST_F(BoundedDeduplicationCacheTestSuite, RollbackInFlightRestoresUnseenState) {
    BoundedDeduplicationCache cache(100, std::chrono::minutes(10), 4);
    auto now = std::chrono::steady_clock::now();

    auto event = build_sample_event(make_uuid_string(200));
    auto fp = domain::EventPayloadFingerprint::compute(event);

    auto acq1 = cache.try_acquire(event.event_id, fp, now);
    EXPECT_EQ(acq1.decision, DedupAcquireResult::Decision::AcquiredNewInFlight);

    PersistAckResult fail_res{.status = IngestionOutcomeStatus::PersistenceFailed,
                              .event_id = event.event_id,
                              .error_code = "UNAVAILABLE",
                              .diagnostic_message = "ClickHouse down"};

    cache.rollback_in_flight(event.event_id, fail_res);
    EXPECT_EQ(cache.size(), 0u);

    // Re-acquire gets fresh slot
    auto acq2 = cache.try_acquire(event.event_id, fp, now);
    EXPECT_EQ(acq2.decision, DedupAcquireResult::Decision::AcquiredNewInFlight);
}

} // namespace securecloud::audit::ingestion::testing