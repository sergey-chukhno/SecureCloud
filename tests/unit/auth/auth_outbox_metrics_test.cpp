#include "auth/audit/auth_outbox_diagnostics.hpp"
#include "auth/audit/auth_outbox_metrics.hpp"
#include "auth/audit/auth_outbox_relay.hpp"
#include "auth/domain/audit_event.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/service/audit_event_publisher.hpp"
#include "auth/service/outbox_event_mapper.hpp"

#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace securecloud::auth::audit::test {
namespace {

using ::testing::_;
using ::testing::HasSubstr;
using ::testing::NiceMock;
using ::testing::Not;
using ::testing::Return;

class MockOutboxRepository : public repository::IAuthOutboxRepository {
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

class MockAuditClient : public IAuthAuditClient {
  public:
    MOCK_METHOD(AuditBatchSubmitResult, submit_batch,
                (const std::vector<::securecloud::audit::v1::AuditEventProto>& events), (override));
};

domain::AuthOutboxEntity make_sample_entity(std::chrono::seconds age_offset = std::chrono::seconds(0)) {
    const auto uid = domain::Uuid::generate_v7();
    const auto did = domain::Uuid::generate_v7();
    const auto sid = domain::Uuid::generate_v7();
    const auto ev = domain::AuditEvent::login_succeeded(uid, "alice@securecloud.io", did, sid, "198.51.100.42");
    auto entity = service::OutboxEventMapper::to_outbox_entity(ev);
    entity.created_at = std::chrono::system_clock::now() - age_offset;
    return entity;
}

TEST(AuthOutboxMetricsTest, ToPrometheusText_ExportsAllRequiredMetricsAndBoundedLabels) {
    AuthOutboxMetrics metrics;
    metrics.reset();

    metrics.set_pending_events(14);
    metrics.record_event_staged(StagingCategory::Transactional, 10);
    metrics.record_event_staged(StagingCategory::Autonomous, 4);
    metrics.record_events_delivered(25);
    metrics.record_delivery_batch(BatchOutcome::Success, 3);
    metrics.record_delivery_batch(BatchOutcome::Retryable, 1);
    metrics.record_delivery_batch(BatchOutcome::Rejected, 2);
    metrics.record_retry(5);
    metrics.record_quarantined(QuarantineReason::MalformedPayload, 1);
    metrics.record_quarantined(QuarantineReason::SchemaValidation, 2);
    metrics.record_quarantined(QuarantineReason::RemoteRejected, 3);
    metrics.record_purged(120);
    metrics.set_oldest_pending_age_seconds(4.5);

    const std::string text = metrics.to_prometheus_text();

    EXPECT_THAT(text, HasSubstr("# TYPE auth_outbox_pending_events gauge"));
    EXPECT_THAT(text, HasSubstr("auth_outbox_pending_events 14\n"));

    EXPECT_THAT(text, HasSubstr("# TYPE auth_outbox_events_staged_total counter"));
    EXPECT_THAT(text, HasSubstr("auth_outbox_events_staged_total{category=\"transactional\"} 10\n"));
    EXPECT_THAT(text, HasSubstr("auth_outbox_events_staged_total{category=\"autonomous\"} 4\n"));

    EXPECT_THAT(text, HasSubstr("# TYPE auth_outbox_events_delivered_total counter"));
    EXPECT_THAT(text, HasSubstr("auth_outbox_events_delivered_total 25\n"));

    EXPECT_THAT(text, HasSubstr("# TYPE auth_outbox_delivery_batches_total counter"));
    EXPECT_THAT(text, HasSubstr("auth_outbox_delivery_batches_total{outcome=\"success\"} 3\n"));
    EXPECT_THAT(text, HasSubstr("auth_outbox_delivery_batches_total{outcome=\"retryable\"} 1\n"));
    EXPECT_THAT(text, HasSubstr("auth_outbox_delivery_batches_total{outcome=\"rejected\"} 2\n"));

    EXPECT_THAT(text, HasSubstr("# TYPE auth_outbox_retries_total counter"));
    EXPECT_THAT(text, HasSubstr("auth_outbox_retries_total 5\n"));

    EXPECT_THAT(text, HasSubstr("# TYPE auth_outbox_quarantined_total counter"));
    EXPECT_THAT(text, HasSubstr("auth_outbox_quarantined_total{reason=\"malformed_payload\"} 1\n"));
    EXPECT_THAT(text, HasSubstr("auth_outbox_quarantined_total{reason=\"schema_validation\"} 2\n"));
    EXPECT_THAT(text, HasSubstr("auth_outbox_quarantined_total{reason=\"remote_rejected\"} 3\n"));

    EXPECT_THAT(text, HasSubstr("# TYPE auth_outbox_purged_total counter"));
    EXPECT_THAT(text, HasSubstr("auth_outbox_purged_total 120\n"));

    EXPECT_THAT(text, HasSubstr("# TYPE auth_outbox_oldest_pending_age_seconds gauge"));
    EXPECT_THAT(text, HasSubstr("auth_outbox_oldest_pending_age_seconds 4.5\n"));
}

TEST(AuthOutboxMetricsTest, PublisherAndRelay_AccuratelyTrackLifecycleMetricsAndAge) {
    AuthOutboxMetrics metrics;
    AuthOutboxDiagnostics diagnostics;
    std::ostringstream log_sink;
    diagnostics.set_output_stream(&log_sink);

    auto repo = std::make_shared<NiceMock<MockOutboxRepository>>();
    auto client = std::make_shared<NiceMock<MockAuditClient>>();

    // 1. Stage 2 autonomous events via OutboxAuditEventPublisher
    EXPECT_CALL(*repo, stage_event(_)).Times(2);
    service::OutboxAuditEventPublisher publisher(repo, "auth-1", nullptr, &metrics);

    const auto uid = domain::Uuid::generate_v7();
    const auto did = domain::Uuid::generate_v7();
    const auto sid = domain::Uuid::generate_v7();
    const auto domain_ev = domain::AuditEvent::login_succeeded(uid, "bob@securecloud.io", did, sid, "198.51.100.99");

    publisher.publish(domain_ev);
    publisher.publish(domain_ev);

    EXPECT_EQ(metrics.events_staged_total(StagingCategory::Autonomous), 2u);
    EXPECT_EQ(metrics.pending_events(), 2);

    // 2. Relay batch: 1 valid delivered, 1 permanently rejected, oldest age ~12s
    const auto e1 = make_sample_entity(std::chrono::seconds(12));
    const auto e2 = make_sample_entity(std::chrono::seconds(2));

    EXPECT_CALL(*repo, fetch_and_lease_pending_batch(_, _))
        .WillOnce(Return(std::vector<domain::AuthOutboxEntity>{e1, e2}));

    AuditBatchSubmitResult partial_res;
    partial_res.rpc_success = true;
    partial_res.status = grpc::Status::OK;
    partial_res.accepted_count = 1;
    partial_res.rejected_count = 1;
    partial_res.rejected_event_ids = {e2.event_id.to_string()};

    EXPECT_CALL(*client, submit_batch(_)).WillOnce(Return(partial_res));
    EXPECT_CALL(*repo, mark_published(e1.event_id)).WillOnce(Return(true));
    EXPECT_CALL(*repo, mark_quarantined(e2.event_id, _)).WillOnce(Return(true));

    AuthOutboxRelay relay(repo, client, {}, "auth-1", &metrics, &diagnostics);
    EXPECT_EQ(relay.poll_and_dispatch(), 2u);

    EXPECT_EQ(metrics.pending_events(), 0);
    EXPECT_EQ(metrics.events_delivered_total(), 1u);
    EXPECT_EQ(metrics.quarantined_total(QuarantineReason::RemoteRejected), 1u);
    EXPECT_EQ(metrics.delivery_batches_total(BatchOutcome::Rejected), 1u);
    EXPECT_GE(metrics.oldest_pending_age_seconds(), 11.0);
    EXPECT_LE(metrics.oldest_pending_age_seconds(), 15.0);

    // 3. Retention purge increments purged_total
    EXPECT_CALL(*repo, purge_published_older_than(_, _)).WillOnce(Return(17u));
    EXPECT_EQ(relay.purge_old_published_records(), 17u);
    EXPECT_EQ(metrics.purged_total(), 17u);

    diagnostics.set_output_stream(nullptr);
}

TEST(AuthOutboxDiagnosticsTest, ScrubsAllSecretsPiiAndCredentialsFromLogs) {
    AuthOutboxDiagnostics diagnostics;
    std::ostringstream log_sink;
    diagnostics.set_output_stream(&log_sink);

    EXPECT_EQ(AuthOutboxDiagnostics::scrub_sensitive_data("password=SuperSecret123!"), "[REDACTED_SENSITIVE_DATA]");
    EXPECT_EQ(AuthOutboxDiagnostics::scrub_sensitive_data("Bearer eyJhbGciOiJIUzI1NiJ9.aaa.bbb"),
              "[REDACTED_SENSITIVE_DATA]");
    EXPECT_EQ(AuthOutboxDiagnostics::scrub_sensitive_data("-----BEGIN PRIVATE KEY-----"), "[REDACTED_SENSITIVE_DATA]");
    EXPECT_EQ(AuthOutboxDiagnostics::scrub_sensitive_data("totp_code=482910"), "[REDACTED_SENSITIVE_DATA]");
    EXPECT_EQ(AuthOutboxDiagnostics::scrub_sensitive_data("recovery_code=ABCD-EFGH"), "[REDACTED_SENSITIVE_DATA]");
    EXPECT_EQ(AuthOutboxDiagnostics::scrub_sensitive_data("Failed login for alice@securecloud.io"),
              "[REDACTED_SENSITIVE_DATA]");
    EXPECT_EQ(AuthOutboxDiagnostics::scrub_sensitive_data("gRPC UNAVAILABLE: connection refused"),
              "gRPC UNAVAILABLE: connection refused");

    diagnostics.log_circuit_trip(3, std::chrono::milliseconds(1000), "019a0000-0000-7000-8000-000000000001",
                                 "RPC failed with refresh_token=rt_secret_999");

    const std::string output = log_sink.str();
    EXPECT_THAT(output, HasSubstr("Outbox relay circuit trip"));
    EXPECT_THAT(output, HasSubstr("correlation_id=019a0000-0000-7000-8000-000000000001"));
    EXPECT_THAT(output, HasSubstr("[REDACTED_SENSITIVE_DATA]"));
    EXPECT_THAT(output, Not(HasSubstr("rt_secret_999")));
    EXPECT_THAT(output, Not(HasSubstr("refresh_token")));

    diagnostics.set_output_stream(nullptr);
}

} // namespace
} // namespace securecloud::auth::audit::test
