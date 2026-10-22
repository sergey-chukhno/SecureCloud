#include "domain/sensitive_data_guard.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::domain::test {

    TEST(SensitiveDataGuardTest, RejectsForbiddenKeyTerms) {
        const std::array<std::string, 5> forbidden_keys = {
            "user_password", "auth_token", "api_secret", "private_key", "mfa_code"
        };

        for (const auto& key : forbidden_keys) {
            AuditEvent event;
            event.metadata[key] = "some_value";

            auto res = SensitiveDataGuard::inspect(event);
            EXPECT_FALSE(res.is_valid());
        }
    }

    TEST(SensitiveDataGuardTest, RejectsPemKeysAndJwtValues) {
        // PEM private key rejection
        {
            AuditEvent event;
            event.metadata["cert_info"] = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...";

            auto res = SensitiveDataGuard::inspect(event);
            EXPECT_FALSE(res.is_valid());
        }
        // JWT token pattern rejection
        {
            AuditEvent event;
            event.metadata["session_data"] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

            auto res = SensitiveDataGuard::inspect(event);
            EXPECT_FALSE(res.is_valid());
        }
    }

    TEST(SensitiveDataGuardTest, SanitizeDiagnosticRedactsSecrets) {
        std::string raw_log = "Error during auth with password=SuperSecret123 and -----BEGIN PRIVATE KEY----- key material";
        std::string sanitized = SensitiveDataGuard::sanitize_diagnostic(raw_log);

        EXPECT_EQ(sanitized.find("SuperSecret123"), std::string::npos);
        EXPECT_EQ(sanitized.find("-----BEGIN PRIVATE KEY-----"), std::string::npos);
        EXPECT_NE(sanitized.find("[REDACTED]"), std::string::npos);
    }

} // namespace securecloud::audit::domain::test