#include "files/db/files_connection_pool.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::files::db {
namespace {

/// Mock database connection handle for unit testing pool mechanics
class MockDbConnection : public IDbConnection {
public:
    explicit MockDbConnection(std::string id, bool is_open = true, bool ping_success = true)
        : id_(std::move(id)), is_open_(is_open), ping_success_(ping_success) {}

    [[nodiscard]] bool is_open() const noexcept override {
        return is_open_;
    }

    void close() noexcept override {
        is_open_ = false;
        close_count_++;
    }

    [[nodiscard]] bool execute_ping(std::chrono::milliseconds /*timeout*/) override {
        ping_count_++;
        return is_open_ && ping_success_;
    }

    [[nodiscard]] const std::string& connection_id() const noexcept override {
        return id_;
    }

    void set_ping_success(bool success) noexcept {
        ping_success_ = success;
    }

    [[nodiscard]] size_t close_count() const noexcept {
        return close_count_;
    }

    [[nodiscard]] size_t ping_count() const noexcept {
        return ping_count_;
    }

private:
    std::string id_;
    bool is_open_{true};
    bool ping_success_{true};
    size_t close_count_{0};
    size_t ping_count_{0};
};

ConnectionFactory make_mock_factory(std::atomic<size_t>& created_count, bool ping_success = true) {
    return [&created_count, ping_success](const ConnectionPoolConfig& /*cfg*/,
                                          const std::string& id) -> std::unique_ptr<IDbConnection> {
        created_count++;
        return std::make_unique<MockDbConnection>(id, true, ping_success);
    };
}

TEST(FilesDbConnectionPoolTest, ConfigValidationEnforcesPort5432SecurityInvariant) {
    // Valid configuration targeting port 5433 (SecureCloud PostgreSQL 17 dev)
    ConnectionPoolConfig valid_cfg;
    valid_cfg.host = "127.0.0.1";
    valid_cfg.port = 5433;
    valid_cfg.min_connections = 2;
    valid_cfg.max_connections = 10;
    EXPECT_NO_THROW(valid_cfg.validate());

    // Host 5432 invariant: Must fail closed to prevent touching host PostgreSQL 14
    ConnectionPoolConfig forbidden_localhost;
    forbidden_localhost.host = "localhost";
    forbidden_localhost.port = 5432;
    EXPECT_THROW(forbidden_localhost.validate(), PortForbiddenException);

    ConnectionPoolConfig forbidden_loopback;
    forbidden_loopback.host = "127.0.0.1";
    forbidden_loopback.port = 5432;
    EXPECT_THROW(forbidden_loopback.validate(), PortForbiddenException);

    ConnectionPoolConfig forbidden_docker_host;
    forbidden_docker_host.host = "host.docker.internal";
    forbidden_docker_host.port = 5432;
    EXPECT_THROW(forbidden_docker_host.validate(), PortForbiddenException);

    // Min connections exceeding max connections
    ConnectionPoolConfig invalid_bounds;
    invalid_bounds.min_connections = 10;
    invalid_bounds.max_connections = 2;
    EXPECT_THROW(invalid_bounds.validate(), std::invalid_argument);

    // Max connections equal to zero
    ConnectionPoolConfig zero_max;
    zero_max.max_connections = 0;
    EXPECT_THROW(zero_max.validate(), std::invalid_argument);
}

TEST(FilesDbConnectionPoolTest, ConfigPopulatesFromFilesConfig) {
    FilesConfig files_cfg;
    files_cfg.db_host = "127.0.0.1";
    files_cfg.db_port = 5433;
    files_cfg.db_name = "securecloud_files";
    files_cfg.db_user = "files_user";
    files_cfg.db_password = common::configuration::SecretString("test_secret_pass");

    ConnectionPoolConfig pool_cfg = ConnectionPoolConfig::from_files_config(files_cfg);
    EXPECT_EQ(pool_cfg.host, "127.0.0.1");
    EXPECT_EQ(pool_cfg.port, 5433);
    EXPECT_EQ(pool_cfg.db_name, "securecloud_files");
    EXPECT_EQ(pool_cfg.db_user, "files_user");
    EXPECT_EQ(pool_cfg.db_password.expose_unredacted_secret(), "test_secret_pass");
    EXPECT_NO_THROW(pool_cfg.validate());
}

TEST(FilesDbConnectionPoolTest, PoolInitializationPrewarmsMinConnections) {
    std::atomic<size_t> created_count{0};
    ConnectionPoolConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 5433;
    cfg.min_connections = 3;
    cfg.max_connections = 8;

    FilesDbConnectionPool pool(cfg, make_mock_factory(created_count));

    EXPECT_EQ(pool.state(), PoolState::OPEN);
    EXPECT_EQ(pool.total_connections(), 3);
    EXPECT_EQ(pool.available_connections(), 3);
    EXPECT_EQ(pool.active_leases(), 0);
    EXPECT_EQ(created_count.load(), 3);
}

TEST(FilesDbConnectionPoolTest, RAIIPooledConnectionLeasingAndReturn) {
    std::atomic<size_t> created_count{0};
    ConnectionPoolConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 5433;
    cfg.min_connections = 2;
    cfg.max_connections = 5;

    FilesDbConnectionPool pool(cfg, make_mock_factory(created_count));

    {
        // 1. Acquire lease
        PooledConnection conn = pool.acquire();
        EXPECT_TRUE(conn.is_valid());
        EXPECT_TRUE(static_cast<bool>(conn));
        EXPECT_FALSE(conn.connection_id().empty());
        EXPECT_EQ(pool.available_connections(), 1);
        EXPECT_EQ(pool.active_leases(), 1);
        EXPECT_EQ(pool.total_connections(), 2);

        // 2. Move construction
        PooledConnection moved_conn(std::move(conn));
        EXPECT_TRUE(moved_conn.is_valid());
        EXPECT_FALSE(conn.is_valid()); // moved-from is invalid
        EXPECT_EQ(pool.active_leases(), 1);

        // 3. Move assignment
        PooledConnection target;
        target = std::move(moved_conn);
        EXPECT_TRUE(target.is_valid());
        EXPECT_FALSE(moved_conn.is_valid());
        EXPECT_EQ(pool.active_leases(), 1);

        // Target goes out of scope here
    }

    // 4. Upon scope exit, connection is automatically returned to pool
    EXPECT_EQ(pool.active_leases(), 0);
    EXPECT_EQ(pool.available_connections(), 2);
    EXPECT_EQ(pool.total_connections(), 2);
}

TEST(FilesDbConnectionPoolTest, DynamicExpansionUpToMaxConnections) {
    std::atomic<size_t> created_count{0};
    ConnectionPoolConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 5433;
    cfg.min_connections = 2;
    cfg.max_connections = 4;

    FilesDbConnectionPool pool(cfg, make_mock_factory(created_count));
    EXPECT_EQ(pool.total_connections(), 2);

    std::vector<PooledConnection> leases;
    for (size_t i = 0; i < 4; ++i) {
        leases.push_back(pool.acquire());
    }

    EXPECT_EQ(pool.total_connections(), 4);
    EXPECT_EQ(pool.active_leases(), 4);
    EXPECT_EQ(pool.available_connections(), 0);
    EXPECT_EQ(created_count.load(), 4);

    leases.clear(); // Return all leases

    EXPECT_EQ(pool.active_leases(), 0);
    EXPECT_EQ(pool.available_connections(), 4);
    EXPECT_EQ(pool.total_connections(), 4);
}

TEST(FilesDbConnectionPoolTest, AcquisitionTimeoutWhenPoolIsExhausted) {
    std::atomic<size_t> created_count{0};
    ConnectionPoolConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 5433;
    cfg.min_connections = 1;
    cfg.max_connections = 2;
    cfg.acquire_timeout = std::chrono::milliseconds(50);

    FilesDbConnectionPool pool(cfg, make_mock_factory(created_count));

    PooledConnection lease1 = pool.acquire();
    PooledConnection lease2 = pool.acquire();

    EXPECT_EQ(pool.active_leases(), 2);
    EXPECT_EQ(pool.available_connections(), 0);

    // Third acquire must time out
    const auto start = std::chrono::steady_clock::now();
    EXPECT_THROW((void)pool.acquire(), PoolTimeoutException);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

    EXPECT_GE(elapsed.count(), 40); // Blocked for approximately acquire_timeout
    EXPECT_EQ(pool.active_leases(), 2);
}

TEST(FilesDbConnectionPoolTest, ConcurrentContentionAcrossMultipleThreads) {
    std::atomic<size_t> created_count{0};
    ConnectionPoolConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 5433;
    cfg.min_connections = 2;
    cfg.max_connections = 4;
    cfg.acquire_timeout = std::chrono::milliseconds(2000);

    FilesDbConnectionPool pool(cfg, make_mock_factory(created_count));

    constexpr size_t k_num_threads = 12;
    constexpr size_t k_iterations_per_thread = 20;
    std::atomic<size_t> successful_acquisitions{0};
    std::vector<std::thread> workers;
    workers.reserve(k_num_threads);

    for (size_t t = 0; t < k_num_threads; ++t) {
        workers.emplace_back([&pool, &successful_acquisitions]() {
            for (size_t i = 0; i < k_iterations_per_thread; ++i) {
                PooledConnection conn = pool.acquire();
                EXPECT_TRUE(conn.is_valid());
                successful_acquisitions++;
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        });
    }

    for (auto& w : workers) {
        if (w.joinable()) {
            w.join();
        }
    }

    EXPECT_EQ(successful_acquisitions.load(), k_num_threads * k_iterations_per_thread);
    EXPECT_EQ(pool.active_leases(), 0);
    EXPECT_EQ(pool.available_connections(), pool.total_connections());
}

TEST(FilesDbConnectionPoolTest, DedicatedHealthPingImmuneToWorkerPoolExhaustion) {
    std::atomic<size_t> created_count{0};
    ConnectionPoolConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 5433;
    cfg.min_connections = 1;
    cfg.max_connections = 1;
    cfg.acquire_timeout = std::chrono::milliseconds(50);

    FilesDbConnectionPool pool(cfg, make_mock_factory(created_count));

    // Exhaust worker pool completely
    PooledConnection worker_lease = pool.acquire();
    EXPECT_EQ(pool.available_connections(), 0);
    EXPECT_EQ(pool.active_leases(), 1);

    // Independent health ping must succeed despite worker pool starvation
    EXPECT_TRUE(pool.ping(std::chrono::milliseconds(100)));

    // Ping should have created its own dedicated health connection
    EXPECT_EQ(created_count.load(), 2); // 1 worker + 1 health
    EXPECT_EQ(pool.active_leases(), 1);
}

TEST(FilesDbConnectionPoolTest, LifecycleDrainAndCloseOperations) {
    std::atomic<size_t> created_count{0};
    ConnectionPoolConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 5433;
    cfg.min_connections = 2;
    cfg.max_connections = 3;

    FilesDbConnectionPool pool(cfg, make_mock_factory(created_count));

    PooledConnection lease = pool.acquire();
    EXPECT_EQ(pool.active_leases(), 1);

    // Initiate drain
    pool.drain();
    EXPECT_EQ(pool.state(), PoolState::DRAINING);
    EXPECT_EQ(pool.available_connections(), 0); // Idle connections closed

    // Acquires during drain must be rejected immediately
    EXPECT_THROW((void)pool.acquire(), PoolDrainingException);

    // Returning active lease during drain is safe
    lease = PooledConnection(); // Destructs lease, returns connection, decrements active_leases_ to 0
    EXPECT_EQ(pool.active_leases(), 0);

    // Close pool completely
    pool.close();
    EXPECT_EQ(pool.state(), PoolState::CLOSED);

    // Operations after close
    EXPECT_THROW((void)pool.acquire(), PoolClosedException);
    EXPECT_FALSE(pool.ping());
}

TEST(FilesDbConnectionPoolTest, DiscardUnhealthyConnectionUponReturn) {
    std::atomic<size_t> created_count{0};
    ConnectionPoolConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 5433;
    cfg.min_connections = 2;
    cfg.max_connections = 4;

    FilesDbConnectionPool pool(cfg, make_mock_factory(created_count));
    EXPECT_EQ(pool.total_connections(), 2);

    {
        PooledConnection conn = pool.acquire();
        EXPECT_EQ(pool.active_leases(), 1);
        conn.mark_unhealthy(); // Mark as dirty/broken
        // Destructor calls return_connection with is_healthy = false
    }

    // Unhealthy connection must be destroyed and discarded, not returned to idle pool
    EXPECT_EQ(pool.active_leases(), 0);
    EXPECT_EQ(pool.available_connections(), 1);
    EXPECT_EQ(pool.total_connections(), 1);
}

} // namespace
} // namespace securecloud::files::db
