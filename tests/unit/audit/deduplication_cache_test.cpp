#include "ingestion/deduplication_cache.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::ingestion::testing {

class DeduplicationCacheTest : public ::testing::Test {
  protected:
    domain::AuditEvent build_sample_event(const std::string& uuid_str, const std::string& actor) {
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
};

TEST_F(DeduplicationCacheTest, LifecycleTransitionsNewToCommitted) {
    BoundedDeduplicationCache cache(100, std::chrono::minutes(10), 4);
    auto now = std::chrono::steady_clock::now();

    auto event = build_sample_event("018f6e4a-7b3c-7000-8000-000000000001", "user_1");
    auto fp = domain::EventPayloadFingerprint::compute(event);

    // 1. First attempt: AcquiredNewInFlight
    auto acq1 = cache.try_acquire(event.event_id, fp, now);
    EXPECT_EQ(acq1.decision, DedupAcquireResult::Decision::AcquiredNewInFlight);
    EXPECT_NE(acq1.primary_promise, nullptr);
    EXPECT_EQ(cache.in_flight_count(), 1u);
    EXPECT_EQ(cache.committed_count(), 0u);

    // 2. Second attempt while IN_FLIGHT: CoalescedInFlight
    auto acq2 = cache.try_acquire(event.event_id, fp, now);
    EXPECT_EQ(acq2.decision, DedupAcquireResult::Decision::CoalescedInFlight);
    EXPECT_EQ(acq2.primary_promise, nullptr);

    // 3. Batch committed in ClickHouse
    auto received_at = std::chrono::system_clock::now();
    cache.mark_committed(event.event_id, received_at, now);

    EXPECT_EQ(cache.in_flight_count(), 0u);
    EXPECT_EQ(cache.committed_count(), 1u);

    // 4. Coalesced waiter receives result from shared_future
    auto ack = acq2.in_flight_future.get();
    EXPECT_EQ(ack.status, IngestionOutcomeStatus::DuplicateCoalesced);
    EXPECT_EQ(ack.event_id, event.event_id);
    EXPECT_EQ(ack.received_at, received_at);

    // 5. Subsequent attempt after commit: AlreadyCommitted
    auto acq3 = cache.try_acquire(event.event_id, fp, now);
    EXPECT_EQ(acq3.decision, DedupAcquireResult::Decision::AlreadyCommitted);
    EXPECT_EQ(acq3.committed_received_at, received_at);
}

TEST_F(DeduplicationCacheTest, PayloadConflictDetection) {
    BoundedDeduplicationCache cache(100, std::chrono::minutes(10), 4);
    auto now = std::chrono::steady_clock::now();

    auto event1 = build_sample_event("018f6e4a-7b3c-7000-8000-000000000002", "user_1");
    auto fp1 = domain::EventPayloadFingerprint::compute(event1);

    auto acq1 = cache.try_acquire(event1.event_id, fp1, now);
    EXPECT_EQ(acq1.decision, DedupAcquireResult::Decision::AcquiredNewInFlight);

    // Same event_id but different payload (actor_id = "user_2")
    auto event2 = build_sample_event("018f6e4a-7b3c-7000-8000-000000000002", "user_2");
    auto fp2 = domain::EventPayloadFingerprint::compute(event2);

    auto acq2 = cache.try_acquire(event1.event_id, fp2, now);
    EXPECT_EQ(acq2.decision, DedupAcquireResult::Decision::PayloadConflict);
}

TEST_F(DeduplicationCacheTest, RollbackInFlightRestoresUnseenState) {
    BoundedDeduplicationCache cache(100, std::chrono::minutes(10), 4);
    auto now = std::chrono::steady_clock::now();

    auto event = build_sample_event("018f6e4a-7b3c-7000-8000-000000000003", "user_1");
    auto fp = domain::EventPayloadFingerprint::compute(event);

    auto acq1 = cache.try_acquire(event.event_id, fp, now);
    EXPECT_EQ(acq1.decision, DedupAcquireResult::Decision::AcquiredNewInFlight);

    auto acq2 = cache.try_acquire(event.event_id, fp, now);
    EXPECT_EQ(acq2.decision, DedupAcquireResult::Decision::CoalescedInFlight);

    PersistAckResult failure{.status = IngestionOutcomeStatus::PersistenceFailed,
                             .event_id = event.event_id,
                             .error_code = "UNAVAILABLE",
                             .diagnostic_message = "ClickHouse connection refused"};

    cache.rollback_in_flight(event.event_id, failure);
    EXPECT_EQ(cache.size(), 0u);

    // Coalesced future receives failure
    auto ack = acq2.in_flight_future.get();
    EXPECT_EQ(ack.status, IngestionOutcomeStatus::PersistenceFailed);
    EXPECT_EQ(ack.error_code, "UNAVAILABLE");

    // Retry acquires slot cleanly as new
    auto acq_retry = cache.try_acquire(event.event_id, fp, now);
    EXPECT_EQ(acq_retry.decision, DedupAcquireResult::Decision::AcquiredNewInFlight);
}

TEST_F(DeduplicationCacheTest, TtlExpirationAndLruEviction) {
    BoundedDeduplicationCache cache(64, std::chrono::minutes(10), 1); // 1 shard, capacity 64
    auto now = std::chrono::steady_clock::now();

    auto event1 = build_sample_event("018f6e4a-7b3c-7000-8000-000000000010", "user_1");
    auto fp1 = domain::EventPayloadFingerprint::compute(event1);

    cache.try_acquire(event1.event_id, fp1, now);
    cache.mark_committed(event1.event_id, std::chrono::system_clock::now(), now);

    // Advance time past 10-minute TTL
    auto future_now = now + std::chrono::minutes(11);

    size_t evicted = cache.evict_expired(future_now);
    EXPECT_EQ(evicted, 1u);
    EXPECT_EQ(cache.committed_count(), 0u);

    // After eviction, event_id is UNSEEN again
    auto acq_after_ttl = cache.try_acquire(event1.event_id, fp1, future_now);
    EXPECT_EQ(acq_after_ttl.decision, DedupAcquireResult::Decision::AcquiredNewInFlight);
}

} // namespace securecloud::audit::ingestion::testing