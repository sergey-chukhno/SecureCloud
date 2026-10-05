#include "auth/auth_config.hpp"
#include "auth/db/pooled_connection.hpp"
#include "auth/db/postgres_connection_pool.hpp"
#include "securecloud/health/health_status_manager.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <type_traits>

namespace securecloud::auth::db::test {

class ConnectionPoolTest : public ::testing::Test {
  protected:
    AuthConfig make_dummy_auth_config() {
        AuthConfig config;
        config.db_host = "127.0.0.1";
        config.db_port = 5433; // Isolated dev port (never 5432)
        config.db_name = "securecloud_auth_test";
        config.db_user = "auth_user";
        config.db_password = common::configuration::SecretString("test_password");
        return config;
    }

    ConnectionPoolConfig make_fast_config() {
        ConnectionPoolConfig config;
        config.min_connections = 0; // 0 to avoid attempting a real database connection during constructor
        config.max_connections = 2;
        config.acquire_timeout = std::chrono::milliseconds{100};
        config.connect_timeout = std::chrono::seconds{1};
        config.statement_timeout = std::chrono::milliseconds{100};
        return config;
    }
};

// 1. Validate default configuration parameters and exception class hierarchy
TEST_F(ConnectionPoolTest, DefaultConfigurationAndExceptionTypes) {
    ConnectionPoolConfig config;
    EXPECT_EQ(config.min_connections, 2);
    EXPECT_EQ(config.max_connections, 10);
    EXPECT_EQ(config.acquire_timeout, std::chrono::milliseconds{5000});
    EXPECT_EQ(config.connect_timeout, std::chrono::seconds{1});
    EXPECT_EQ(config.statement_timeout, std::chrono::milliseconds{250});

    // Ensure custom exceptions properly derive from std::runtime_error
    static_assert(std::is_base_of_v<std::runtime_error, ConnectionAcquisitionTimeoutException>);
    static_assert(std::is_base_of_v<std::runtime_error, PoolShuttingDownException>);

    ConnectionAcquisitionTimeoutException timeout_ex("Acquisition timed out");
    EXPECT_STREQ(timeout_ex.what(), "Acquisition timed out");

    PoolShuttingDownException shutdown_ex("Pool is closing");
    EXPECT_STREQ(shutdown_ex.what(), "Pool is closing");
}

// 2. Validate move-only semantics for PooledConnection leases
TEST_F(ConnectionPoolTest, PooledConnectionMoveSemantics) {
    static_assert(!std::is_copy_constructible_v<PooledConnection>);
    static_assert(!std::is_copy_assignable_v<PooledConnection>);
    static_assert(std::is_move_constructible_v<PooledConnection>);
    static_assert(std::is_move_assignable_v<PooledConnection>);

    PooledConnection empty_conn;
    EXPECT_FALSE(empty_conn);
    EXPECT_EQ(empty_conn.get(), nullptr);

    PooledConnection moved_conn = std::move(empty_conn);
    EXPECT_FALSE(moved_conn);
    EXPECT_EQ(moved_conn.get(), nullptr);
}

// 3. Validate ping() noexcept contract in an isolated environment (no active PostgreSQL instance)
TEST_F(ConnectionPoolTest, PingIsNoexceptAndHandlesUnreachableDatabase) {
    AuthConfig auth_cfg = make_dummy_auth_config();
    ConnectionPoolConfig pool_cfg = make_fast_config();

    // In an offline test environment without PostgreSQL running on port 5433,
    // ensure ping() safely returns false without throwing unhandled exceptions.
    EXPECT_NO_THROW({
        PostgresConnectionPool pool(auth_cfg, pool_cfg);
        bool is_healthy = pool.ping();
        EXPECT_FALSE(is_healthy);
    });
}

// 4. Validate HealthStatusManager integration via ReadinessEvaluator callback
TEST_F(ConnectionPoolTest, IntegratesWithHealthStatusManager) {
    using common::health::HealthStatusManager;

    HealthStatusManager health_mgr("auth-service");
    EXPECT_FALSE(health_mgr.is_ready());

    AuthConfig auth_cfg = make_dummy_auth_config();
    ConnectionPoolConfig pool_cfg = make_fast_config();

    PostgresConnectionPool pool(auth_cfg, pool_cfg);

    // Register pool.ping() as the service readiness evaluator
    health_mgr.set_readiness_evaluator([&pool]() noexcept { return pool.ping(); });

    // Test non-blocking readiness evaluation
    bool ready = health_mgr.evaluate_readiness();
    EXPECT_EQ(ready, pool.ping());
    EXPECT_FALSE(ready);
}

// 5. Validate Port 5432 Host Isolation Guard
TEST_F(ConnectionPoolTest, EnforcesPort5432SecurityInvariant) {
    AuthConfig forbidden_cfg = make_dummy_auth_config();
    forbidden_cfg.db_host = "localhost";
    forbidden_cfg.db_port = 5432;

    ConnectionPoolConfig pool_cfg = make_fast_config();
    EXPECT_THROW((PostgresConnectionPool(forbidden_cfg, pool_cfg)), PortForbiddenException);

    forbidden_cfg.db_host = "127.0.0.1";
    EXPECT_THROW((PostgresConnectionPool(forbidden_cfg, pool_cfg)), PortForbiddenException);
}

// 6. Validate configuration bounds validation
TEST_F(ConnectionPoolTest, InvalidPoolConfigThrows) {
    AuthConfig auth_cfg = make_dummy_auth_config();
    ConnectionPoolConfig pool_cfg = make_fast_config();
    pool_cfg.max_connections = 0;
    EXPECT_THROW((PostgresConnectionPool(auth_cfg, pool_cfg)), std::invalid_argument);

    pool_cfg.max_connections = 2;
    pool_cfg.min_connections = 5;
    EXPECT_THROW((PostgresConnectionPool(auth_cfg, pool_cfg)), std::invalid_argument);
}

// 7. Validate shutdown state and acquire rejection
TEST_F(ConnectionPoolTest, ShutdownTransitionsStateAndRejectsAcquires) {
    AuthConfig auth_cfg = make_dummy_auth_config();
    ConnectionPoolConfig pool_cfg = make_fast_config();

    PostgresConnectionPool pool(auth_cfg, pool_cfg);
    EXPECT_FALSE(pool.ping());

    pool.shutdown(std::chrono::milliseconds{50});
    EXPECT_THROW((void)pool.acquire(), PoolShuttingDownException);
    EXPECT_FALSE(pool.ping());
}

} // namespace securecloud::auth::db::test