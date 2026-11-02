#include "ingestion/acknowledgement_manager.hpp"
#include "ingestion/deduplication_cache.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::ingestion::testing {

class AcknowledgementManagerTest : public ::testing::Test {
  protected:
    domain::AuditEvent build_sample_event(const std::string& uuid_str) {
        domain::AuditEvent event;
        event.event_id = domain::EventId::from_string(uuid_str).value();
        event.occurred_at = std::chrono::system_clock::now();
        event.received_at = std::chrono::system_clock::now();
        event.event_type = "user.login";
        event.severity = domain::Severity::Info;
        event.producer_service = domain::ProducerService::Auth;
        event.producer_instance = "auth-01";
        event.actor_type = domain::ActorType::User;
        event.actor_id = "user_1";
        event.target_type = domain::TargetType::Service;
        event.target_id = "srv-01";
        event.correlation_id = "corr-100";
        return event;
    }
};

TEST_F(AcknowledgementManagerTest, BatchPersistedMarksCacheCommitted) {
    auto cache = std::make_shared<BoundedDeduplicationCache>(100, std::chrono::minutes(10), 4);
    AcknowledgementManager ack_mgr(cache);
    auto now = std::chrono::steady_clock::now();

    auto event = build_sample_event("018f6e4a-7b3c-7000-8000-000000000010");
    auto fp = domain::EventPayloadFingerprint::compute(event);

    auto acq = cache->try_acquire(event.event_id, fp, now);
    EXPECT_EQ(acq.decision, DedupAcquireResult::Decision::AcquiredNewInFlight);

    ack_mgr.on_batch_persisted({event}, now);

    EXPECT_EQ(cache->committed_count(), 1u);
    EXPECT_EQ(cache->in_flight_count(), 0u);
}

TEST_F(AcknowledgementManagerTest, BatchFailedRollsBackCacheInFlight) {
    auto cache = std::make_shared<BoundedDeduplicationCache>(100, std::chrono::minutes(10), 4);
    AcknowledgementManager ack_mgr(cache);
    auto now = std::chrono::steady_clock::now();

    auto event = build_sample_event("018f6e4a-7b3c-7000-8000-000000000011");
    auto fp = domain::EventPayloadFingerprint::compute(event);

    auto acq = cache->try_acquire(event.event_id, fp, now);
    EXPECT_EQ(acq.decision, DedupAcquireResult::Decision::AcquiredNewInFlight);

    repository::RepositoryBatchWriteResult failure{.status = repository::RepositoryWriteStatus::DeterministicFailure,
                                                   .error_code = "UNAVAILABLE",
                                                   .sanitized_reason = "Connection refused"};

    ack_mgr.on_batch_failed({event}, failure);

    EXPECT_EQ(cache->size(), 0u);

    // Caller future receives failure result
    auto ack_res = acq.in_flight_future.get();
    EXPECT_EQ(ack_res.status, IngestionOutcomeStatus::PersistenceFailed);
    EXPECT_EQ(ack_res.error_code, "UNAVAILABLE");
}

TEST_F(AcknowledgementManagerTest, AmbiguousFailureMapsToAmbiguousStatus) {
    auto cache = std::make_shared<BoundedDeduplicationCache>(100, std::chrono::minutes(10), 4);
    AcknowledgementManager ack_mgr(cache);
    auto now = std::chrono::steady_clock::now();

    auto event = build_sample_event("018f6e4a-7b3c-7000-8000-000000000012");
    auto fp = domain::EventPayloadFingerprint::compute(event);

    auto acq = cache->try_acquire(event.event_id, fp, now);

    repository::RepositoryBatchWriteResult failure{.status = repository::RepositoryWriteStatus::AmbiguousOutcome,
                                                   .error_code = "DEADLINE_EXCEEDED",
                                                   .sanitized_reason = "HTTP POST socket timeout"};

    ack_mgr.on_batch_failed({event}, failure);

    EXPECT_EQ(cache->size(), 0u);

    auto ack_res = acq.in_flight_future.get();
    EXPECT_EQ(ack_res.status, IngestionOutcomeStatus::PersistenceAmbiguous);
    EXPECT_EQ(ack_res.error_code, "DEADLINE_EXCEEDED");
}

TEST_F(AcknowledgementManagerTest, InFlightReservationGuardRollsBackWhenUndismissed) {
    auto cache = std::make_shared<BoundedDeduplicationCache>(100, std::chrono::minutes(10), 4);
    auto now = std::chrono::steady_clock::now();

    auto event = build_sample_event("018f6e4a-7b3c-7000-8000-000000000013");
    auto fp = domain::EventPayloadFingerprint::compute(event);

    auto acq = cache->try_acquire(event.event_id, fp, now);

    PersistAckResult default_failure{.status = IngestionOutcomeStatus::QueueOverloaded,
                                     .event_id = event.event_id,
                                     .error_code = "RESOURCE_EXHAUSTED",
                                     .diagnostic_message = "Ingestion queue saturated"};

    {
        InFlightReservationGuard guard(cache, event.event_id, default_failure);
        // Scope ends without calling guard.dismiss()
    }

    EXPECT_EQ(cache->size(), 0u);

    auto ack_res = acq.in_flight_future.get();
    EXPECT_EQ(ack_res.status, IngestionOutcomeStatus::QueueOverloaded);
    EXPECT_EQ(ack_res.error_code, "RESOURCE_EXHAUSTED");
}

} // namespace securecloud::audit::ingestion::testing