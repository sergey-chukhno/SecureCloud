#include "securecloud/configuration/config_parser.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/secret_string.hpp"
#include "securecloud/configuration/validation_error.hpp"

#include <gtest/gtest.h>
#include <sstream>

namespace securecloud::common::configuration {

namespace {

constexpr uint16_t k_test_port_1 = 1;
constexpr uint16_t k_test_port_80 = 80;
constexpr uint16_t k_test_port_50051 = 50051;
constexpr uint16_t k_test_port_65535 = 65535;

constexpr uint64_t k_min_duration_ms = 100;
constexpr uint64_t k_max_duration_ms = 10000;
constexpr uint64_t k_expected_duration_ms = 5000;

constexpr std::size_t k_secret_size = 10;
constexpr std::size_t k_expected_port_errors = 7;
constexpr std::size_t k_expected_bool_errors = 5;
constexpr std::size_t k_expected_duration_errors = 4;

} // namespace

TEST(ConfigParserTest, ParsesValidUint16Ports) {
    ValidationResult errors;

    auto p1 = ConfigParser::parse_uint16("PORT", "1", errors);
    ASSERT_TRUE(p1.has_value());
    if (p1.has_value()) {
        EXPECT_EQ(p1.value(), k_test_port_1);
    }

    auto p2 = ConfigParser::parse_uint16("PORT", "80", errors);
    ASSERT_TRUE(p2.has_value());
    if (p2.has_value()) {
        EXPECT_EQ(p2.value(), k_test_port_80);
    }

    auto p3 = ConfigParser::parse_uint16("PORT", "50051", errors);
    ASSERT_TRUE(p3.has_value());
    if (p3.has_value()) {
        EXPECT_EQ(p3.value(), k_test_port_50051);
    }

    auto p4 = ConfigParser::parse_uint16("PORT", "65535", errors);
    ASSERT_TRUE(p4.has_value());
    if (p4.has_value()) {
        EXPECT_EQ(p4.value(), k_test_port_65535);
    }

    EXPECT_TRUE(errors.is_valid());
}

TEST(ConfigParserTest, RejectsOutOfRangeAndMalformedPorts) {
    ValidationResult errors;

    EXPECT_FALSE(ConfigParser::parse_uint16("PORT", "0", errors).has_value());
    EXPECT_FALSE(ConfigParser::parse_uint16("PORT", "65536", errors).has_value());
    EXPECT_FALSE(ConfigParser::parse_uint16("PORT", "100000", errors).has_value());
    EXPECT_FALSE(ConfigParser::parse_uint16("PORT", "-1", errors).has_value());
    EXPECT_FALSE(ConfigParser::parse_uint16("PORT", "abc", errors).has_value());
    EXPECT_FALSE(ConfigParser::parse_uint16("PORT", "50051xyz", errors).has_value());
    EXPECT_FALSE(ConfigParser::parse_uint16("PORT", "", errors).has_value());

    EXPECT_TRUE(errors.has_errors());
    EXPECT_EQ(errors.errors().size(), k_expected_port_errors);
}

TEST(ConfigParserTest, ParsesCaseInsensitiveBooleans) {
    ValidationResult errors;

    EXPECT_EQ(ConfigParser::parse_bool("FLAG", "true", errors), true);
    EXPECT_EQ(ConfigParser::parse_bool("FLAG", "True", errors), true);
    EXPECT_EQ(ConfigParser::parse_bool("FLAG", "TRUE", errors), true);
    EXPECT_EQ(ConfigParser::parse_bool("FLAG", "1", errors), true);

    EXPECT_EQ(ConfigParser::parse_bool("FLAG", "false", errors), false);
    EXPECT_EQ(ConfigParser::parse_bool("FLAG", "False", errors), false);
    EXPECT_EQ(ConfigParser::parse_bool("FLAG", "FALSE", errors), false);
    EXPECT_EQ(ConfigParser::parse_bool("FLAG", "0", errors), false);

    EXPECT_TRUE(errors.is_valid());
}

TEST(ConfigParserTest, RejectsMalformedBooleans) {
    ValidationResult errors;

    EXPECT_FALSE(ConfigParser::parse_bool("FLAG", "yes", errors).has_value());
    EXPECT_FALSE(ConfigParser::parse_bool("FLAG", "no", errors).has_value());
    EXPECT_FALSE(ConfigParser::parse_bool("FLAG", "enable", errors).has_value());
    EXPECT_FALSE(ConfigParser::parse_bool("FLAG", "2", errors).has_value());
    EXPECT_FALSE(ConfigParser::parse_bool("FLAG", "", errors).has_value());

    EXPECT_TRUE(errors.has_errors());
    EXPECT_EQ(errors.errors().size(), k_expected_bool_errors);
}

TEST(ConfigParserTest, ParsesBoundedDurationsInMilliseconds) {
    ValidationResult errors;

    auto d1 = ConfigParser::parse_duration_ms("TIMEOUT", "5000", errors, k_min_duration_ms, k_max_duration_ms);
    ASSERT_TRUE(d1.has_value());
    if (d1.has_value()) {
        EXPECT_EQ(d1.value().count(), k_expected_duration_ms);
    }

    // Below minimum
    EXPECT_FALSE(
        ConfigParser::parse_duration_ms("TIMEOUT", "50", errors, k_min_duration_ms, k_max_duration_ms).has_value());

    // Above maximum
    EXPECT_FALSE(
        ConfigParser::parse_duration_ms("TIMEOUT", "20000", errors, k_min_duration_ms, k_max_duration_ms).has_value());

    // Non-numeric
    EXPECT_FALSE(
        ConfigParser::parse_duration_ms("TIMEOUT", "5s", errors, k_min_duration_ms, k_max_duration_ms).has_value());
    EXPECT_FALSE(
        ConfigParser::parse_duration_ms("TIMEOUT", "", errors, k_min_duration_ms, k_max_duration_ms).has_value());

    EXPECT_TRUE(errors.has_errors());
    EXPECT_EQ(errors.errors().size(), k_expected_duration_errors);
}

TEST(ConfigParserTest, ValidatesFilesystemPaths) {
    ValidationResult errors;

    auto p1 = ConfigParser::parse_path("PATH", "/etc/securecloud/certs/ca.crt", errors, false);
    ASSERT_TRUE(p1.has_value());
    if (p1.has_value()) {
        EXPECT_EQ(p1.value().string(), "/etc/securecloud/certs/ca.crt");
    }

    // Empty path
    EXPECT_FALSE(ConfigParser::parse_path("PATH", "", errors, false).has_value());

    // Non-existent path with must_exist=true
    EXPECT_FALSE(ConfigParser::parse_path("PATH", "/non/existent/file.txt", errors, true).has_value());

    EXPECT_TRUE(errors.has_errors());
}

TEST(ConfigParserTest, ParsesStringsWithEmptyConstraint) {
    ValidationResult errors;

    auto s1 = ConfigParser::parse_string("NAME", "gateway", errors, false);
    ASSERT_TRUE(s1.has_value());
    if (s1.has_value()) {
        EXPECT_EQ(s1.value(), "gateway");
    }

    // Empty string rejected when allow_empty=false
    EXPECT_FALSE(ConfigParser::parse_string("NAME", "", errors, false).has_value());

    // Empty string allowed when allow_empty=true
    auto s2 = ConfigParser::parse_string("OPTIONAL", "", errors, true);
    ASSERT_TRUE(s2.has_value());
    if (s2.has_value()) {
        EXPECT_EQ(s2.value(), "");
    }
}

TEST(SecretStringTest, RedactsOutputInStreams) {
    SecretString secret("super-secret-password-123");

    std::ostringstream oss;
    oss << secret;
    EXPECT_EQ(oss.str(), "[REDACTED]");
    EXPECT_NE(oss.str(), "super-secret-password-123");
}

TEST(SecretStringTest, RequiresExplicitUnredactedAccess) {
    SecretString secret("my-api-key");
    EXPECT_EQ(secret.expose_unredacted_secret(), "my-api-key");
    EXPECT_FALSE(secret.empty());
    EXPECT_EQ(secret.size(), k_secret_size);
}

TEST(SecretStringTest, CopyAndMoveSemantics) {
    SecretString original("database-password");
    SecretString copy = original; // NOLINT(performance-unnecessary-copy-initialization)
    EXPECT_EQ(copy.expose_unredacted_secret(), "database-password");
    EXPECT_EQ(original.expose_unredacted_secret(), "database-password");

    SecretString moved = std::move(original);
    EXPECT_EQ(moved.expose_unredacted_secret(), "database-password");
    EXPECT_TRUE(original.empty()); // NOLINT(bugprone-use-after-move)
}

TEST(SecretStringTest, ExcludesSecretFromValidationErrorFormatting) {
    ValidationResult errors;
    errors.add_error("AUTH_DB_PASSWORD", "cannot be empty");

    std::string err_str = errors.to_string();
    EXPECT_NE(err_str.find("AUTH_DB_PASSWORD"), std::string::npos);
    EXPECT_NE(err_str.find("cannot be empty"), std::string::npos);
    EXPECT_EQ(err_str.find("super-secret"), std::string::npos);
}

TEST(ConfigurationSourceTest, InMemorySourceStoresAndRetrievesKeys) {
    InMemoryConfigurationSource source;
    EXPECT_FALSE(source.get("FOO").has_value());

    source.set("FOO", "bar");
    auto foo_val = source.get("FOO");
    ASSERT_TRUE(foo_val.has_value());
    if (foo_val.has_value()) {
        EXPECT_EQ(foo_val.value(), "bar");
    }

    source.unset("FOO");
    EXPECT_FALSE(source.get("FOO").has_value());

    source.set("KEY1", "VAL1");
    source.set("KEY2", "VAL2");
    source.clear();
    EXPECT_FALSE(source.get("KEY1").has_value());
    EXPECT_FALSE(source.get("KEY2").has_value());
}

TEST(ConfigurationSourceTest, ProcessEnvironmentSourceNullTerminationSafe) {
    ProcessEnvironmentSource source;
    EXPECT_FALSE(source.get("SECURECLOUD_NON_EXISTENT_VAR_XYZ_123").has_value());
}

} // namespace securecloud::common::configuration
