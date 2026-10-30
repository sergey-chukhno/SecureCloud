#include "repository/audit_repository_exceptions.hpp"
#include "repository/clickhouse_client.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::repository::testing {

TEST(ClickHouseClientTest, ConnectionFailureToUnreachableHost) {
    ClickHouseConfig config;
    config.host = "127.0.0.1";
    config.port = 59999; // Non-existent port
    config.connect_timeout_ms = 200;
    config.request_timeout_ms = 200;

    ClickHouseClient client(config);

    EXPECT_THROW(
        { (void)client.execute_query("SELECT 1", nullptr, std::chrono::milliseconds(200)); },
        ClickHouseConnectionException);
}

TEST(ClickHouseClientTest, PingFailsOnUnreachableHost) {
    ClickHouseConfig config;
    config.host = "127.0.0.1";
    config.port = 59999;
    config.connect_timeout_ms = 100;

    ClickHouseClient client(config);
    EXPECT_FALSE(client.ping(std::chrono::milliseconds(100)));
}

} // namespace securecloud::audit::repository::testing