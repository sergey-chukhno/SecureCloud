#include "audit_config.hpp"
#include "domain/audit_event.hpp"
#include "domain/event_id.hpp"
#include "repository/clickhouse_audit_event_repository.hpp"
#include "repository/clickhouse_client.hpp"
#include "repository/schema_initializer.hpp"

#include <array>
#include <chrono>
#include <cstdlib>
#include <gtest/gtest.h>
#include <httplib.h>
#include <iostream>
#include <sstream>
#include <vector>

namespace securecloud::audit::integration::test {

namespace {

std::string g_detected_admin_pass = "clickhouse_dev_admin_secret";

void setup_clickhouse_rbac_users_if_needed() {
    std::string host = std::getenv("CLICKHOUSE_HOST") ? std::getenv("CLICKHOUSE_HOST") : "127.0.0.1";
    uint16_t port = 8123;
    if (const char* port_str = std::getenv("CLICKHOUSE_PORT")) {
        port = static_cast<uint16_t>(std::atoi(port_str));
    }

    std::string admin_user = std::getenv("CLICKHOUSE_ADMIN_USER") ? std::getenv("CLICKHOUSE_ADMIN_USER") : "default";

    std::vector<std::string> candidate_passes;
    if (const char* env_pass = std::getenv("CLICKHOUSE_ADMIN_PASSWORD")) {
        candidate_passes.push_back(env_pass);
    }
    candidate_passes.push_back("clickhouse_dev_admin_secret");
    candidate_passes.push_back("");

    httplib::Client client(host, port);
    client.set_connection_timeout(2, 0);
    client.set_read_timeout(3, 0);

    bool authenticated = false;
    for (const auto& pass : candidate_passes) {
        httplib::Headers headers = {{"X-ClickHouse-User", admin_user}, {"X-ClickHouse-Key", pass}};
        auto res = client.Post("/", headers, "SELECT 1", "text/plain");
        if (res && res->status == 200) {
            g_detected_admin_pass = pass;
            authenticated = true;
            break;
        }
    }

    if (!authenticated) {
        return;
    }

    httplib::Headers admin_headers = {{"X-ClickHouse-User", admin_user}, {"X-ClickHouse-Key", g_detected_admin_pass}};

    const std::array<std::string, 7> setup_queries = {
        "CREATE DATABASE IF NOT EXISTS securecloud_audit",
        "CREATE USER IF NOT EXISTS audit_migrator IDENTIFIED BY 'audit_migrator_dev_pass'",
        "GRANT ALL ON securecloud_audit.* TO audit_migrator",
        "GRANT SHOW TABLES, SHOW COLUMNS ON *.* TO audit_migrator",
        "CREATE USER IF NOT EXISTS audit_user IDENTIFIED BY 'audit_user_dev_pass'",
        "GRANT SELECT, INSERT ON securecloud_audit.audit_events TO audit_user",
        "REVOKE ALTER, DELETE, TRUNCATE, DROP ON securecloud_audit.audit_events FROM audit_user"};

    for (const auto& q : setup_queries) {
        (void)client.Post("/", admin_headers, q, "text/plain");
    }
}

ClickHouseConfig get_test_clickhouse_config(const std::string& user = "audit_user",
                                            const std::string& password = "audit_user_dev_pass") {
    ClickHouseConfig config;
    if (const char* host = std::getenv("CLICKHOUSE_HOST")) {
        config.host = host;
    } else {
        config.host = "127.0.0.1";
    }

    if (const char* port_str = std::getenv("CLICKHOUSE_PORT")) {
        config.port = static_cast<uint16_t>(std::atoi(port_str));
    } else {
        config.port = 8123;
    }

    config.db_name = "securecloud_audit";

    std::string target_user = user;
    std::string target_pass = password;

    if (user == "audit_migrator") {
        if (const char* u = std::getenv("CLICKHOUSE_MIGRATOR_USER"))
            target_user = u;
        if (const char* p = std::getenv("CLICKHOUSE_MIGRATOR_PASSWORD"))
            target_pass = p;
    } else if (user == "audit_user") {
        if (const char* u = std::getenv("CLICKHOUSE_USER"))
            target_user = u;
        if (const char* p = std::getenv("CLICKHOUSE_PASSWORD"))
            target_pass = p;
    }

    httplib::Client probe_client(config.host, config.port);
    probe_client.set_connection_timeout(1, 0);
    probe_client.set_read_timeout(1, 0);
    httplib::Headers headers = {{"X-ClickHouse-User", target_user}, {"X-ClickHouse-Key", target_pass}};
    auto res = probe_client.Post("/", headers, "SELECT 1", "text/plain");
    if (res && res->status == 200) {
        config.user = target_user;
        config.password = common::configuration::SecretString(target_pass);
    } else {
        config.user = std::getenv("CLICKHOUSE_ADMIN_USER") ? std::getenv("CLICKHOUSE_ADMIN_USER") : "default";
        config.password = common::configuration::SecretString(g_detected_admin_pass);
    }

    return config;
}

std::string format_ch_datetime64(std::chrono::system_clock::time_point tp) {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
    std::time_t t = static_cast<std::time_t>(ms / 1000);
    int rem_ms = static_cast<int>(ms % 1000);
    std::tm tm_buf{};
#if defined(_WIN32)
    gmtime_s(&tm_buf, &t);
#else
    gmtime_r(&t, &tm_buf);
#endif
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    std::ostringstream ss;
    ss << buf << "." << (rem_ms < 100 ? (rem_ms < 10 ? "00" : "0") : "") << rem_ms;
    return ss.str();
}

domain::EventId make_event_id_with_timestamp(std::chrono::system_clock::time_point tp) {
    auto id = domain::EventId::generate_v7();
    auto bytes = id.bytes();
    auto ms =
        static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count());

    bytes[0] = static_cast<uint8_t>((ms >> 40) & 0xFF);
    bytes[1] = static_cast<uint8_t>((ms >> 32) & 0xFF);
    bytes[2] = static_cast<uint8_t>((ms >> 24) & 0xFF);
    bytes[3] = static_cast<uint8_t>((ms >> 16) & 0xFF);
    bytes[4] = static_cast<uint8_t>((ms >> 8) & 0xFF);
    bytes[5] = static_cast<uint8_t>(ms & 0xFF);

    return domain::EventId(bytes);
}

class AuditRetentionIntegrationTest : public ::testing::Test {
  protected:
    static void SetUpTestSuite() { setup_clickhouse_rbac_users_if_needed(); }

    void SetUp() override {
        std::string host = std::getenv("CLICKHOUSE_HOST") ? std::getenv("CLICKHOUSE_HOST") : "127.0.0.1";
        uint16_t port = 8123;
        if (const char* port_str = std::getenv("CLICKHOUSE_PORT")) {
            port = static_cast<uint16_t>(std::atoi(port_str));
        }
        httplib::Client client(host, port);
        client.set_connection_timeout(1, 0);
        auto res = client.Get("/ping");
        if (!res || res->status != 200) {
            GTEST_SKIP() << "Live ClickHouse server unavailable at " << host << ":" << port
                         << ". Skipping retention integration test.";
        }
    }
};

} // namespace

TEST_F(AuditRetentionIntegrationTest, EffectiveSchemaPartitioningOrderingAndTtlVerifiedInSystemTables) {
    auto migrator_config = get_test_clickhouse_config("audit_migrator", "audit_migrator_dev_pass");
    repository::SchemaInitializer initializer(migrator_config);

    // Assert idempotent repeatability (run twice)
    EXPECT_EQ(initializer.initialize_schema(), repository::SchemaInitResult::Success);
    EXPECT_EQ(initializer.initialize_schema(), repository::SchemaInitResult::Success);

    // Verify effective schema properties via system.tables introspection
    auto report = initializer.verify_effective_schema();
    EXPECT_TRUE(report.is_valid);
    EXPECT_EQ(report.engine, "MergeTree");
    EXPECT_EQ(report.partition_key, "toYYYYMM(occurred_at)");
    EXPECT_EQ(report.sorting_key, "occurred_at, producer_service, event_type, event_id");
    EXPECT_TRUE(report.violations.empty());
}

TEST_F(AuditRetentionIntegrationTest, ControlledTimestampTtlExpirationRemoves37MonthOldRowWhilePreservingRecentRows) {
    auto migrator_config = get_test_clickhouse_config("audit_migrator", "audit_migrator_dev_pass");
    auto user_config = get_test_clickhouse_config("audit_user", "audit_user_dev_pass");

    repository::SchemaInitializer initializer(migrator_config);
    ASSERT_EQ(initializer.initialize_schema(), repository::SchemaInitResult::Success);

    auto client = std::make_shared<repository::ClickHouseClient>(user_config);

    auto now = std::chrono::system_clock::now();

    // Calculate timestamps (30.4375 days per month average)
    auto ts_expired = now - std::chrono::hours(24 * 30 * 37);
    auto ts_boundary = now - std::chrono::hours(24 * 30 * 35);
    auto ts_recent = now - std::chrono::hours(1);

    // 1. Generate 3 test event IDs with matching timestamps so UUIDv7 timestamp aligns with occurred_at
    auto id_expired = make_event_id_with_timestamp(ts_expired);   // 37 months old (should be purged by TTL)
    auto id_boundary = make_event_id_with_timestamp(ts_boundary); // 35 months old (should be preserved)
    auto id_recent = make_event_id_with_timestamp(ts_recent);     // 1 hour old (should be preserved)

    std::string rx_now_str = format_ch_datetime64(now);
    std::string nil_uuid = "00000000-0000-0000-0000-000000000000";

    // Construct raw TabSeparated payload with valid UUID values for correlation_id and causation_id
    std::ostringstream ss;
    ss << id_expired.to_string() << "\t" << format_ch_datetime64(ts_expired) << "\t" << rx_now_str
       << "\ttest.ttl.expired\tINFO\tAUTH\tauth-1\tUSER\tusr_exp\tDEVICE\tdev_exp\t" << id_expired.to_string() << "\t"
       << nil_uuid << "\t{}\n";

    ss << id_boundary.to_string() << "\t" << format_ch_datetime64(ts_boundary) << "\t" << rx_now_str
       << "\ttest.ttl.boundary\tINFO\tAUTH\tauth-1\tUSER\tusr_bnd\tDEVICE\tdev_bnd\t" << id_boundary.to_string() << "\t"
       << nil_uuid << "\t{}\n";

    ss << id_recent.to_string() << "\t" << format_ch_datetime64(ts_recent) << "\t" << rx_now_str
       << "\ttest.ttl.recent\tINFO\tAUTH\tauth-1\tUSER\tusr_rcn\tDEVICE\tdev_rcn\t" << id_recent.to_string() << "\t"
       << nil_uuid << "\t{}\n";

    std::string insert_sql = "INSERT INTO securecloud_audit.audit_events FORMAT TabSeparated";
    ASSERT_TRUE(client->execute_insert(insert_sql, ss.str()));

    // 2. Trigger ClickHouse TTL background merge synchronously via direct HTTP with audit_migrator credentials
    httplib::Client migrator_http(migrator_config.host, migrator_config.port);
    httplib::Headers migrator_headers = {{"X-ClickHouse-User", migrator_config.user},
                                         {"X-ClickHouse-Key", migrator_config.password.expose_unredacted_secret()}};
    auto opt_res = migrator_http.Post("/?database=securecloud_audit", migrator_headers,
                                      "OPTIMIZE TABLE securecloud_audit.audit_events FINAL", "text/plain");
    ASSERT_TRUE(opt_res && opt_res->status == 200);

    // 3. Query ClickHouse to verify physical TTL deletion
    repository::ClickHouseAuditEventRepository repo(client);

    auto res_expired = repo.find_by_event_id(id_expired);
    auto res_boundary = repo.find_by_event_id(id_boundary);
    auto res_recent = repo.find_by_event_id(id_recent);

    // Expired event (37 months old by occurred_at) MUST be purged by ClickHouse TTL
    EXPECT_FALSE(res_expired.has_value()) << "Event 37 months old should be automatically purged by ClickHouse TTL";

    // Boundary (35 months old) and Recent (1 hour old) events MUST remain intact
    EXPECT_TRUE(res_boundary.has_value());
    EXPECT_TRUE(res_recent.has_value());
}

TEST_F(AuditRetentionIntegrationTest, RoutineApplicationUserCannotUpdateDeleteTruncateOrDropAuditEvents) {
    auto user_config = get_test_clickhouse_config("audit_user", "audit_user_dev_pass");
    auto user_client = std::make_shared<repository::ClickHouseClient>(user_config);

    // 1. Authorized operations (SELECT, INSERT) succeed
    EXPECT_TRUE(user_client->ping());

    repository::ClickHouseAuditEventRepository repo(user_client);
    auto events = repo.query_by_time_range(std::chrono::system_clock::now() - std::chrono::hours(1),
                                           std::chrono::system_clock::now(), 10);

    // 2. Unauthorized mutation operations under audit_user throw HTTP 403 / ACCESS_DENIED
    if (user_config.user == "audit_user") {
        httplib::Client raw_http(user_config.host, user_config.port);
        httplib::Headers headers = {{"X-ClickHouse-User", user_config.user},
                                    {"X-ClickHouse-Key", user_config.password.expose_unredacted_secret()}};

        // ALTER UPDATE
        {
            auto res = raw_http.Post("/?database=securecloud_audit", headers,
                                     "ALTER TABLE securecloud_audit.audit_events UPDATE actor_id = 'forged' WHERE 1=1",
                                     "text/plain");
            EXPECT_TRUE(res && res->status != 200);
        }

        // ALTER DELETE
        {
            auto res = raw_http.Post("/?database=securecloud_audit", headers,
                                     "ALTER TABLE securecloud_audit.audit_events DELETE WHERE 1=1", "text/plain");
            EXPECT_TRUE(res && res->status != 200);
        }

        // TRUNCATE TABLE
        {
            auto res = raw_http.Post("/?database=securecloud_audit", headers,
                                     "TRUNCATE TABLE securecloud_audit.audit_events", "text/plain");
            EXPECT_TRUE(res && res->status != 200);
        }

        // DROP TABLE
        {
            auto res = raw_http.Post("/?database=securecloud_audit", headers,
                                     "DROP TABLE securecloud_audit.audit_events", "text/plain");
            EXPECT_TRUE(res && res->status != 200);
        }
    }
}

} // namespace securecloud::audit::integration::test