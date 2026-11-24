#include "files/audit/files_outbox_diagnostics.hpp"
#include "files/audit/files_outbox_metrics.hpp"

#include <algorithm>
#include <gtest/gtest.h>
#include <sstream>

namespace securecloud::files::audit {

TEST(FilesOutboxMetricsTest, ExportsOpenMetricsWithClosedLabelSets) {
    FilesOutboxMetrics metrics;
    metrics.record_staged(FilesOutboxCategory::Transactional, 2);
    metrics.record_staged(FilesOutboxCategory::Autonomous, 1);
    metrics.record_delivered(3);
    metrics.record_batch(FilesOutboxOutcome::Success);
    metrics.record_batch(FilesOutboxOutcome::Retryable);
    metrics.record_batch(FilesOutboxOutcome::Rejected);
    metrics.record_retry(4);
    metrics.record_quarantined(FilesOutboxQuarantineReason::Validation);
    metrics.record_quarantined(FilesOutboxQuarantineReason::Rejected, 2);
    metrics.record_purged(8);
    metrics.set_pending(9);
    metrics.set_oldest_pending_age(12.5);

    const auto text = metrics.to_prometheus_text();
    EXPECT_NE(text.find("files_outbox_events_staged_total{category=\"transactional\"} 2\n"), std::string::npos);
    EXPECT_NE(text.find("files_outbox_events_staged_total{category=\"autonomous\"} 1\n"), std::string::npos);
    EXPECT_NE(text.find("files_outbox_delivery_batches_total{outcome=\"rejected\"} 1\n"), std::string::npos);
    EXPECT_NE(text.find("files_outbox_quarantined_total{reason=\"validation\"} 1\n"), std::string::npos);
    EXPECT_NE(text.find("files_outbox_pending_events 9\n"), std::string::npos);
    EXPECT_NE(text.find("files_outbox_oldest_pending_age_seconds 12.5\n"), std::string::npos);
    EXPECT_NE(text.find("# EOF\n"), std::string::npos);
    EXPECT_EQ(text.find("event_id"), std::string::npos);
}

TEST(FilesOutboxDiagnosticsTest, ScrubsSecretsAndFilenamesFromSyntheticDatabaseErrors) {
    FilesOutboxDiagnostics diagnostics;
    diagnostics.reset_rate_limiters();
    std::ostringstream output;
    diagnostics.set_output_stream(&output);
    diagnostics.log_event(FilesDiagnosticCategory::Lease, "lease_failed", "correlation-1",
                          "db_password=hunter2 Bearer eyJhbGci.abc.def /srv/files/secret.pdf");
    const auto log = output.str();
    EXPECT_NE(log.find("\"correlation_id\":\"correlation-1\""), std::string::npos);
    EXPECT_NE(log.find("[REDACTED_SENSITIVE_DATA]"), std::string::npos);
    EXPECT_EQ(log.find("hunter2"), std::string::npos);
    EXPECT_EQ(log.find("eyJhbGci"), std::string::npos);
    EXPECT_EQ(log.find("secret.pdf"), std::string::npos);
    EXPECT_EQ(std::count(log.begin(), log.end(), '\n'), 1);
    diagnostics.set_output_stream(nullptr);
}

TEST(FilesOutboxDiagnosticsTest, AppliesPerCategoryTokenBucketLimit) {
    FilesOutboxDiagnostics diagnostics;
    diagnostics.reset_rate_limiters();
    std::ostringstream output;
    diagnostics.set_output_stream(&output);
    for (int i = 0; i < 20; ++i) {
        diagnostics.log_event(FilesDiagnosticCategory::Outage, "audit_unavailable", {}, "temporary outage");
    }
    const auto text = output.str();
    EXPECT_EQ(std::count(text.begin(), text.end(), '\n'), 5);
    diagnostics.set_output_stream(nullptr);
}

} // namespace securecloud::files::audit
