#include "auth/audit/auth_audit_mapper.hpp"
#include "auth/audit/auth_outbox_diagnostics.hpp"
#include "auth/audit/auth_outbox_metrics.hpp"
#include "auth/audit/auth_outbox_relay.hpp"
#include "auth/domain/audit_event.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/service/outbox_event_mapper.hpp"

#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace securecloud::auth::audit::test {
namespace {

using domain::AuditEvent;
using domain::AuditEventType;
using domain::Uuid;
using ::testing::HasSubstr;
using ::testing::NiceMock;
using ::testing::Not;

class DummyOutboxRepository : public repository::IAuthOutboxRepository {
  public:
    MOCK_METHOD(void, stage_event, (const domain::AuthOutboxEntity& event, pqxx::transaction_base& tx), (override));
    MOCK_METHOD(void, stage_event, (const domain::AuthOutboxEntity& event), (override));
    MOCK_METHOD(std::vector<domain::AuthOutboxEntity>, fetch_and_lease_pending_batch,
                (std::size_t limit, std::chrono::seconds lease_duration), (override));
    MOCK_METHOD(bool, mark_published, (const domain::Uuid& event_id), (override));
    MOCK_METHOD(bool, mark_failed, (const domain::Uuid& event_id, std::string_view error), (override));
    MOCK_METHOD(bool, mark_quarantined, (const domain::Uuid& event_id, std::string_view reason), (override));
    MOCK_METHOD(std::size_t, purge_published_older_than,
                (std::chrono::system_clock::time_point cutoff, std::size_t batch_size), (override));
    MOCK_METHOD(std::size_t, count_pending, (), (override));
};

class DummyAuditClient : public IAuthAuditClient {
  public:
    MOCK_METHOD(AuditBatchSubmitResult, submit_batch,
                (const std::vector<::securecloud::audit::v1::AuditEventProto>& events), (override));
};

// ============================================================================
// Test 1: Canonical Proto Mapping Fidelity for All 23 Auth Audit Event Types
// ============================================================================

TEST(AuthOutboxTest, CanonicalProtoMappingFidelity_All23EventTypes) {
    const auto uid = Uuid::generate_v7();
    const auto did = Uuid::generate_v7();
    const auto sid = Uuid::generate_v7();
    constexpr std::string_view kEmail = "alice@securecloud.io";
    constexpr std::string_view kIp = "198.51.100.77";

    const std::vector<AuditEvent> all_events = {
        AuditEvent::login_succeeded(uid, kEmail, did, sid, kIp),
        AuditEvent::login_failed(kEmail, "Invalid password", uid, did, kIp),
        AuditEvent::account_disabled_attempt(uid, kEmail, "Account suspended", did, kIp),
        AuditEvent::session_revoked(sid, uid, did, "User logout", kIp),
        AuditEvent::session_expired_attempt(sid, kIp),
        AuditEvent::session_revoked_attempt(sid, kIp),
        AuditEvent::token_refreshed(sid, uid, did, kIp),
        AuditEvent::token_reuse_detected(sid, did, kIp),
        AuditEvent::mfa_enrollment_initiated(uid, kIp),
        AuditEvent::mfa_enrollment_confirmed(uid, kIp),
        AuditEvent::mfa_disabled(uid, kIp),
        AuditEvent::mfa_challenge_created(uid, sid, kIp),
        AuditEvent::mfa_challenge_succeeded(uid, sid, kIp),
        AuditEvent::mfa_challenge_failed(uid, sid, "Invalid TOTP code", kIp),
        AuditEvent::mfa_recovery_code_used(uid, sid, kIp),
        AuditEvent::device_enrolled(uid, did, true, kIp),
        AuditEvent::device_pairing_initiated(uid, did, kIp),
        AuditEvent::device_authorized(uid, did, kIp),
        AuditEvent::device_revoked(uid, did, "Compromised device", kIp),
        AuditEvent::prekeys_updated(uid, did, 100, kIp),
        AuditEvent::signed_prekey_rotated(uid, did, kIp),
        AuditEvent::prekey_inventory_low(uid, did, 10, kIp),
        AuditEvent::prekey_inventory_exhausted(uid, did, kIp),
    };

    ASSERT_EQ(all_events.size(), 23u);

    std::unordered_set<std::string> seen_event_ids;
    std::unordered_set<std::string> seen_event_types;

    for (const auto& domain_event : all_events) {
        const auto entity = service::OutboxEventMapper::to_outbox_entity(domain_event);
        EXPECT_EQ(entity.event_id, domain_event.event_id);
        EXPECT_EQ(entity.event_type, std::string(domain::to_string(domain_event.event_type)));
        EXPECT_EQ(entity.status, domain::OutboxStatus::Pending);

        const auto proto = AuthAuditMapper::to_proto(entity, "auth-unit-1");
        EXPECT_EQ(proto.event_id(), domain_event.event_id.to_string());
        EXPECT_EQ(proto.event_type(), std::string(domain::to_string(domain_event.event_type)));
        EXPECT_EQ(proto.producer_service(), ::securecloud::audit::v1::PRODUCER_SERVICE_AUTH);
        EXPECT_EQ(proto.producer_instance(), "auth-unit-1");
        EXPECT_FALSE(proto.correlation_id().empty());
        EXPECT_GT(proto.occurred_at_ms(), 0);

        seen_event_ids.insert(proto.event_id());
        seen_event_types.insert(proto.event_type());
    }

    EXPECT_EQ(seen_event_ids.size(), 23u);
    EXPECT_EQ(seen_event_types.size(), 23u);
}

// ============================================================================
// Test 2: Sensitive-Data Scrubbing (Tokens, Hashes, Passwords Stripped)
// ============================================================================

TEST(AuthOutboxTest, SensitiveDataScrubbing_StripsPasswordsTokensHashesAndSecrets) {
    const auto uid = Uuid::generate_v7();
    const auto did = Uuid::generate_v7();
    const auto sid = Uuid::generate_v7();

    // Inject sensitive credential material into failure_reason and credential_identifier
    auto ev = AuditEvent::login_failed("alice@securecloud.io",
                                       "Rejected credential: password=SuperSecretPassword123! "
                                       "refresh_token=rt_live_secret_token_987654321 "
                                       "hash=$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA "
                                       "jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
                                       uid, did, "203.0.113.55");
    ev.session_id = sid;

    const auto entity = service::OutboxEventMapper::to_outbox_entity(ev);
    EXPECT_THAT(entity.payload_json, Not(HasSubstr("SuperSecretPassword123!")));
    EXPECT_THAT(entity.payload_json, Not(HasSubstr("rt_live_secret_token_987654321")));
    EXPECT_THAT(entity.payload_json, Not(HasSubstr("$argon2id$")));
    EXPECT_THAT(entity.payload_json, Not(HasSubstr("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")));

    const auto proto = AuthAuditMapper::to_proto(entity, "auth-unit-1");

    const std::string serialized = proto.SerializeAsString();
    EXPECT_THAT(serialized, Not(HasSubstr("SuperSecretPassword123!")));
    EXPECT_THAT(serialized, Not(HasSubstr("rt_live_secret_token_987654321")));
    EXPECT_THAT(serialized, Not(HasSubstr("$argon2id$")));
    EXPECT_THAT(serialized, Not(HasSubstr("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")));

    for (const auto& [key, val] : proto.metadata()) {
        EXPECT_THAT(key, Not(HasSubstr("password")));
        EXPECT_THAT(key, Not(HasSubstr("token")));
        EXPECT_THAT(key, Not(HasSubstr("secret")));
        EXPECT_THAT(val, Not(HasSubstr("SuperSecretPassword123!")));
        EXPECT_THAT(val, Not(HasSubstr("rt_live_secret_token_987654321")));
        EXPECT_THAT(val, Not(HasSubstr("$argon2id$")));
        EXPECT_THAT(val, Not(HasSubstr("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")));
    }

    // Verify diagnostic logger also scrubs secrets
    AuthOutboxDiagnostics diag;
    std::ostringstream log_stream;
    diag.set_output_stream(&log_stream);
    diag.log_quarantine_action(ev.event_id.to_string(), ev.event_id.to_string(), QuarantineReason::SchemaValidation,
                               "Failed with bearer eyJhbGciOiJIUzI1NiJ9.payload.sig and password=SecretPass!");
    diag.set_output_stream(nullptr);

    const std::string logged = log_stream.str();
    EXPECT_THAT(logged, HasSubstr("[REDACTED_SENSITIVE_DATA]"));
    EXPECT_THAT(logged, Not(HasSubstr("SecretPass!")));
    EXPECT_THAT(logged, Not(HasSubstr("eyJhbGciOiJIUzI1NiJ9")));
}

// ============================================================================
// Test 3: Lock-Free Metrics Accuracy & Prometheus Exposition Formatting
// ============================================================================

TEST(AuthOutboxTest, LockFreeMetricsAccuracyAndPrometheusExposition) {
    AuthOutboxMetrics metrics;
    metrics.reset();

    metrics.record_event_staged(StagingCategory::Transactional, 7);
    metrics.record_event_staged(StagingCategory::Autonomous, 3);
    metrics.set_pending_events(10);
    metrics.decrement_pending_events(6);
    metrics.record_events_delivered(6);
    metrics.record_delivery_batch(BatchOutcome::Success, 2);
    metrics.record_delivery_batch(BatchOutcome::Retryable, 1);
    metrics.record_retry(4);
    metrics.record_quarantined(QuarantineReason::RemoteRejected, 1);
    metrics.record_purged(50);
    metrics.set_oldest_pending_age_seconds(12.25);

    EXPECT_EQ(metrics.pending_events(), 4);
    EXPECT_EQ(metrics.events_staged_total(StagingCategory::Transactional), 7u);
    EXPECT_EQ(metrics.events_staged_total(StagingCategory::Autonomous), 3u);
    EXPECT_EQ(metrics.events_delivered_total(), 6u);
    EXPECT_EQ(metrics.delivery_batches_total(BatchOutcome::Success), 2u);
    EXPECT_EQ(metrics.delivery_batches_total(BatchOutcome::Retryable), 1u);
    EXPECT_EQ(metrics.retries_total(), 4u);
    EXPECT_EQ(metrics.quarantined_total(QuarantineReason::RemoteRejected), 1u);
    EXPECT_EQ(metrics.purged_total(), 50u);
    EXPECT_DOUBLE_EQ(metrics.oldest_pending_age_seconds(), 12.25);

    const std::string prom = metrics.to_prometheus_text();
    EXPECT_THAT(prom, HasSubstr("# HELP auth_outbox_pending_events"));
    EXPECT_THAT(prom, HasSubstr("# TYPE auth_outbox_pending_events gauge\nauth_outbox_pending_events 4\n"));
    EXPECT_THAT(prom, HasSubstr("auth_outbox_events_staged_total{category=\"transactional\"} 7\n"));
    EXPECT_THAT(prom, HasSubstr("auth_outbox_events_staged_total{category=\"autonomous\"} 3\n"));
    EXPECT_THAT(prom, HasSubstr("auth_outbox_events_delivered_total 6\n"));
    EXPECT_THAT(prom, HasSubstr("auth_outbox_delivery_batches_total{outcome=\"success\"} 2\n"));
    EXPECT_THAT(prom, HasSubstr("auth_outbox_delivery_batches_total{outcome=\"retryable\"} 1\n"));
    EXPECT_THAT(prom, HasSubstr("auth_outbox_retries_total 4\n"));
    EXPECT_THAT(prom, HasSubstr("auth_outbox_quarantined_total{reason=\"remote_rejected\"} 1\n"));
    EXPECT_THAT(prom, HasSubstr("auth_outbox_purged_total 50\n"));
    EXPECT_THAT(prom, HasSubstr("auth_outbox_oldest_pending_age_seconds 12.25\n"));
}

// ============================================================================
// Test 4: Exponential Backoff Calculation & Jitter Bounds
// ============================================================================

TEST(AuthOutboxTest, ExponentialBackoffCalculationAndJitterBounds) {
    auto repo = std::make_shared<NiceMock<DummyOutboxRepository>>();
    auto client = std::make_shared<NiceMock<DummyAuditClient>>();

    AuthOutboxRelayConfig cfg;
    cfg.initial_backoff = std::chrono::milliseconds(100);
    cfg.max_backoff = std::chrono::milliseconds(800);
    cfg.backoff_multiplier = 2.0;
    cfg.jitter_ratio = 0.20; // ±20%

    AuthOutboxRelay relay(repo, client, cfg);

    EXPECT_EQ(relay.compute_backoff_delay(0).count(), 0);

    // Attempt 1: 100ms ± 20% -> [80, 120]
    for (int i = 0; i < 25; ++i) {
        const auto ms = relay.compute_backoff_delay(1).count();
        EXPECT_GE(ms, 80);
        EXPECT_LE(ms, 120);
    }

    // Attempt 3: 400ms ± 20% -> [320, 480]
    for (int i = 0; i < 25; ++i) {
        const auto ms = relay.compute_backoff_delay(3).count();
        EXPECT_GE(ms, 320);
        EXPECT_LE(ms, 480);
    }

    // Attempt 8: capped at max_backoff 800ms -> [640, 800]
    for (int i = 0; i < 25; ++i) {
        const auto ms = relay.compute_backoff_delay(8).count();
        EXPECT_GE(ms, 640);
        EXPECT_LE(ms, 800);
    }
}

} // namespace
} // namespace securecloud::auth::audit::test
