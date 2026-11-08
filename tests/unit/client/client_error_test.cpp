#include "application/client_error.hpp"
#include "infrastructure/client_logger.hpp"

#include <gtest/gtest.h>
#include <vector>

namespace {

using namespace securecloud::client::application;
using namespace securecloud::client::infrastructure;

TEST(ClientErrorTest, FormattingAndProperties) {
    ClientError err(ClientErrorCode::NetworkUnavailable, ClientErrorCategory::Network, "Cannot reach Gateway",
                    "TCP connection reset", "req-12345");

    EXPECT_EQ(err.code(), ClientErrorCode::NetworkUnavailable);
    EXPECT_EQ(err.category(), ClientErrorCategory::Network);
    EXPECT_EQ(err.user_message(), "Cannot reach Gateway");
    EXPECT_EQ(err.details(), "TCP connection reset");
    EXPECT_EQ(err.correlation_id(), "req-12345");

    const std::string err_str = err.to_string();
    EXPECT_NE(err_str.find("[Network::NetworkUnavailable]"), std::string::npos);
    EXPECT_NE(err_str.find("Cannot reach Gateway"), std::string::npos);
    EXPECT_NE(err_str.find("details: TCP connection reset"), std::string::npos);
    EXPECT_NE(err_str.find("correlation_id: req-12345"), std::string::npos);
}

TEST(ClientErrorTest, FactoryMethods) {
    const auto net_err = ClientError::network("Net error", "details");
    EXPECT_EQ(net_err.category(), ClientErrorCategory::Network);

    const auto timeout_err = ClientError::timeout("Timeout error");
    EXPECT_EQ(timeout_err.code(), ClientErrorCode::ConnectionTimeout);

    const auto auth_err = ClientError::authentication("Auth error");
    EXPECT_EQ(auth_err.category(), ClientErrorCategory::Authentication);

    const auto stor_err = ClientError::storage("Storage error");
    EXPECT_EQ(stor_err.category(), ClientErrorCategory::Storage);

    const auto val_err = ClientError::validation("Val error");
    EXPECT_EQ(val_err.category(), ClientErrorCategory::Validation);

    const auto cry_err = ClientError::crypto("Crypto error");
    EXPECT_EQ(cry_err.category(), ClientErrorCategory::Crypto);

    const auto int_err = ClientError::internal_error("Internal error");
    EXPECT_EQ(int_err.category(), ClientErrorCategory::Internal);
}

TEST(ClientResultTest, NonVoidSuccess) {
    const ClientResult<int> res(42);
    EXPECT_TRUE(res.is_ok());
    EXPECT_FALSE(res.is_error());
    EXPECT_TRUE(static_cast<bool>(res));
    EXPECT_EQ(res.value(), 42);
    EXPECT_EQ(res.value_or(100), 42);
}

TEST(ClientResultTest, NonVoidError) {
    const ClientResult<std::string> res(ClientError::network("Network down"));
    EXPECT_FALSE(res.is_ok());
    EXPECT_TRUE(res.is_error());
    EXPECT_FALSE(static_cast<bool>(res));
    EXPECT_EQ(res.error().user_message(), "Network down");
    EXPECT_EQ(res.value_or("default_val"), "default_val");
}

TEST(ClientResultTest, MonadicAndThenAndTransform) {
    const ClientResult<int> res(10);
    const auto chained = res.and_then([](int v) { return ClientResult<std::string>::ok(std::to_string(v * 2)); });
    EXPECT_TRUE(chained.is_ok());
    EXPECT_EQ(chained.value(), "20");

    const auto transformed = chained.transform([](const std::string& s) { return s + " units"; });
    EXPECT_TRUE(transformed.is_ok());
    EXPECT_EQ(transformed.value(), "20 units");

    const ClientResult<int> failed(ClientError::validation("Invalid input"));
    const auto failed_chain = failed.and_then([](int v) { return ClientResult<int>::ok(v + 1); });
    EXPECT_TRUE(failed_chain.is_error());
    EXPECT_EQ(failed_chain.error().user_message(), "Invalid input");
}

TEST(ClientResultTest, VoidSuccessAndError) {
    const ClientResult<void> ok_res = ClientResult<void>::ok();
    EXPECT_TRUE(ok_res.is_ok());
    EXPECT_FALSE(ok_res.is_error());
    EXPECT_TRUE(static_cast<bool>(ok_res));

    const ClientResult<void> err_res = ClientResult<void>::error(ClientError::storage("Disk full"));
    EXPECT_FALSE(err_res.is_ok());
    EXPECT_TRUE(err_res.is_error());
    EXPECT_FALSE(static_cast<bool>(err_res));
    EXPECT_EQ(err_res.error().user_message(), "Disk full");
}

TEST(ClientLoggerTest, SanitizesBearerToken) {
    const std::string raw = "Authorization: Bearer secret_jwt_token_payload_12345 in request";
    const std::string sanitized = ClientLogger::sanitize(raw);
    EXPECT_EQ(sanitized.find("secret_jwt_token_payload_12345"), std::string::npos);
    EXPECT_NE(sanitized.find("Bearer [REDACTED]"), std::string::npos);
}

TEST(ClientLoggerTest, SanitizesJsonPasswordsAndTokens) {
    const std::string raw = R"({"username":"alice","password":"mypassword123","token":"token_abc_456"})";
    const std::string sanitized = ClientLogger::sanitize(raw);
    EXPECT_EQ(sanitized.find("mypassword123"), std::string::npos);
    EXPECT_EQ(sanitized.find("token_abc_456"), std::string::npos);
    EXPECT_NE(sanitized.find(R"("password":"[REDACTED]")"), std::string::npos);
    EXPECT_NE(sanitized.find(R"("token":"[REDACTED]")"), std::string::npos);
}

TEST(ClientLoggerTest, SanitizesQueryPasswordsAndTokens) {
    const std::string raw = "connect?user=bob&password=supersecret&token=tok12345&mode=fast";
    const std::string sanitized = ClientLogger::sanitize(raw);
    EXPECT_EQ(sanitized.find("supersecret"), std::string::npos);
    EXPECT_EQ(sanitized.find("tok12345"), std::string::npos);
    EXPECT_NE(sanitized.find("password=[REDACTED]"), std::string::npos);
    EXPECT_NE(sanitized.find("token=[REDACTED]"), std::string::npos);
}

TEST(ClientLoggerTest, SanitizesPrivateKeyBlocks) {
    const std::string raw = "Key data: -----BEGIN EC PRIVATE KEY-----\n"
                            "MHcCAQEEIEdi3...fake...key...material\n"
                            "-----END EC PRIVATE KEY-----\n"
                            "finished.";
    const std::string sanitized = ClientLogger::sanitize(raw);
    EXPECT_EQ(sanitized.find("MHcCAQEEIEdi3"), std::string::npos);
    EXPECT_NE(sanitized.find("[REDACTED_PRIVATE_KEY]"), std::string::npos);
}

TEST(ClientLoggerTest, CustomSinkAndLevelFiltering) {
    struct CapturedLog {
        LogLevel level;
        std::string tag;
        std::string message;
        std::string cid;
    };

    std::vector<CapturedLog> logs;
    ClientLogger::set_custom_sink(
        [&logs](LogLevel lvl, std::string_view tag, std::string_view msg, std::string_view cid) {
            logs.push_back({lvl, std::string(tag), std::string(msg), std::string(cid)});
        });

    ClientLogger::set_min_level(LogLevel::Info);

    ClientLogger::debug("TestTag", "This debug log should be filtered out");
    EXPECT_TRUE(logs.empty());

    ClientLogger::info("TestTag", "Info message with Bearer token_secret_999", "cid-777");
    ASSERT_EQ(logs.size(), 1u);
    EXPECT_EQ(logs[0].level, LogLevel::Info);
    EXPECT_EQ(logs[0].tag, "TestTag");
    EXPECT_EQ(logs[0].cid, "cid-777");
    EXPECT_EQ(logs[0].message.find("token_secret_999"), std::string::npos);
    EXPECT_NE(logs[0].message.find("Bearer [REDACTED]"), std::string::npos);

    ClientLogger::reset_sink();
}

} // namespace
