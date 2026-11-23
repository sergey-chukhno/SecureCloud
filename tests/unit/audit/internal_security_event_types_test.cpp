#include "security/internal_security_event_types.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::security::testing {

TEST(InternalSecurityEventTypesTest, EventTypeStringMapping) {
    EXPECT_EQ(to_event_type_string(InternalSecurityEventType::UnauthenticatedConnection),
              "audit.security.auth.unauthenticated_connection");
    EXPECT_EQ(to_event_type_string(InternalSecurityEventType::ProducerIdentityMismatch),
              "audit.security.auth.producer_identity_mismatch");
    EXPECT_EQ(to_event_type_string(InternalSecurityEventType::SensitiveDataDetected),
              "audit.security.payload.sensitive_data_detected");
    EXPECT_EQ(to_event_type_string(InternalSecurityEventType::IngestionQueueSaturated),
              "audit.security.capacity.queue_saturated");
    EXPECT_EQ(to_event_type_string(InternalSecurityEventType::PersistenceStorageFailure),
              "audit.security.storage.persistence_failure");
    EXPECT_EQ(to_event_type_string(InternalSecurityEventType::ServiceStarted),
              "audit.security.lifecycle.service_started");
}

TEST(InternalSecurityEventTypesTest, SeverityMapping) {
    EXPECT_EQ(to_severity(InternalSecurityEventType::UnauthenticatedConnection), domain::Severity::Security);
    EXPECT_EQ(to_severity(InternalSecurityEventType::SensitiveDataDetected), domain::Severity::Critical);
    EXPECT_EQ(to_severity(InternalSecurityEventType::ExcessiveClockSkew), domain::Severity::Warning);
    EXPECT_EQ(to_severity(InternalSecurityEventType::ServiceStarted), domain::Severity::Info);
}

TEST(InternalSecurityEventTypesTest, ProhibitedMetadataKeyDetection) {
    EXPECT_TRUE(is_prohibited_metadata_key("auth_token"));
    EXPECT_TRUE(is_prohibited_metadata_key("api_key"));
    EXPECT_TRUE(is_prohibited_metadata_key("user_password"));
    EXPECT_TRUE(is_prohibited_metadata_key("client_secret"));

    EXPECT_FALSE(is_prohibited_metadata_key("peer_address"));
    EXPECT_FALSE(is_prohibited_metadata_key("rpc_method"));
    EXPECT_FALSE(is_prohibited_metadata_key("error_code"));
}

TEST(InternalSecurityEventTypesTest, MetadataValidationBounds) {
    EXPECT_TRUE(validate_internal_metadata_key_value("rpc_method", "SubmitBatch"));
    EXPECT_FALSE(validate_internal_metadata_key_value("auth_header", "Bearer xyz"));

    std::string long_key(65, 'a');
    EXPECT_FALSE(validate_internal_metadata_key_value(long_key, "val"));

    std::string long_val(257, 'v');
    EXPECT_FALSE(validate_internal_metadata_key_value("valid_key", long_val));

    std::unordered_map<std::string, std::string> metadata;
    for (int i = 0; i < 11; ++i) {
        metadata["key_" + std::to_string(i)] = "val";
    }
    EXPECT_FALSE(validate_internal_metadata(metadata));
}

} // namespace securecloud::audit::security::testing