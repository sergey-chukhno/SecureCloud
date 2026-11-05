#include "telemetry/audit_diagnostics.hpp"

#include <gtest/gtest.h>
#include <iostream>
#include <sstream>

namespace securecloud::audit::telemetry::testing {

class AuditDiagnosticsTest : public ::testing::Test {
  protected:
    void SetUp() override {
        AuditDiagnostics::instance().reset_rate_limiters();
        AuditDiagnostics::instance().set_service_state(lifecycle::DetailedServiceState::Ready);
    }
};

TEST_F(AuditDiagnosticsTest, SanitizesSensitiveDetailData) {
    std::string plain = "normal operational detail";
    std::string sensitive1 = "User attempted login with password SuperSecret123!";
    std::string sensitive2 = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.secret";

    EXPECT_EQ(AuditDiagnostics::sanitize_detail(plain), "normal operational detail");
    EXPECT_EQ(AuditDiagnostics::sanitize_detail(sensitive1), "[REDACTED_SENSITIVE_DATA]");
    EXPECT_EQ(AuditDiagnostics::sanitize_detail(sensitive2), "[REDACTED_SENSITIVE_DATA]");
}

TEST_F(AuditDiagnosticsTest, LogsIngestionRejectionWithCorrelationId) {
    std::ostringstream buffer;
    std::streambuf* old_cout = std::cout.rdbuf(buffer.rdbuf());

    log_ingestion_rejection("clock_skew", "auth", "SubmitAuditEvent", std::make_optional("corr-12345"),
                            "skew_ms=450000");

    std::cout.rdbuf(old_cout);
    std::string output = buffer.str();

    EXPECT_NE(output.find("[SecureCloud] [audit] [WARN]"), std::string::npos);
    EXPECT_NE(output.find("[state=Ready]"), std::string::npos);
    EXPECT_NE(output.find("reason=clock_skew"), std::string::npos);
    EXPECT_NE(output.find("producer=auth"), std::string::npos);
    EXPECT_NE(output.find("correlation_id=corr-12345"), std::string::npos);
}

TEST_F(AuditDiagnosticsTest, RateLimitsRepetitiveLogsWithinOneSecond) {
    std::ostringstream buffer;
    std::streambuf* old_cout = std::cout.rdbuf(buffer.rdbuf());

    for (int i = 0; i < 5; ++i) {
        log_persistence_failure("CLICKHOUSE_TIMEOUT", 100, "Connection timed out", static_cast<uint32_t>(i));
    }

    std::cout.rdbuf(old_cout);
    std::string output = buffer.str();

    size_t count = 0;
    size_t pos = 0;
    while ((pos = output.find("CLICKHOUSE_TIMEOUT", pos)) != std::string::npos) {
        count++;
        pos += 18;
    }

    EXPECT_EQ(count, 1u);
}

} // namespace securecloud::audit::telemetry::testing
