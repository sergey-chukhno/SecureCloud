#include "files/audit/audit_client_interface.hpp"
#include "files/audit/files_outbox_relay.hpp"
#include "files/db/files_connection_pool.hpp"
#include "files/db/migration_runner.hpp"
#include "files/repository/files_outbox_repository.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <gtest/gtest.h>
#include <mutex>
#include <pqxx/pqxx>
#include <random>
#include <thread>
#include <unordered_set>

namespace securecloud::files::integration {
namespace {
std::string uuid_v7() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    const auto ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    std::array<uint8_t, 16> b{};
    for (size_t i = 0; i < 6; ++i)
        b[5 - i] = static_cast<uint8_t>(ms >> (i * 8));
    const auto r1 = rng(), r2 = rng();
    b[6] = static_cast<uint8_t>(0x70u | ((r1 >> 56) & 0x0fu));
    b[7] = static_cast<uint8_t>(r1 >> 48);
    b[8] = static_cast<uint8_t>(0x80u | ((r2 >> 56) & 0x3fu));
    for (size_t i = 9; i < b.size(); ++i)
        b[i] = static_cast<uint8_t>(r2 >> ((15 - i) * 8));
    char out[37]{};
    std::snprintf(out, sizeof(out), "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", b[0], b[1],
                  b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    return out;
}

FilesOutboxEntity make_event() {
    FilesOutboxEntity e;
    e.event_id = uuid_v7();
    e.aggregate_type = "FILE";
    e.aggregate_id = uuid_v7();
    e.event_type = "file.created";
    e.payload_json = "{}";
    e.created_at = std::chrono::system_clock::now();
    return e;
}

class ToggleAuditClient final : public audit::IFilesAuditClient {
  public:
    audit::FilesAuditBatchSubmitResult
    submit_batch(const std::vector<securecloud::audit::v1::AuditEventProto>& events) override {
        audit::FilesAuditBatchSubmitResult result;
        if (!available.load(std::memory_order_acquire)) {
            result.status = grpc::Status(grpc::StatusCode::UNAVAILABLE, "simulated Audit outage");
            return result;
        }
        result.rpc_success = true;
        result.status = grpc::Status::OK;
        result.accepted_count = static_cast<uint32_t>(events.size());
        std::lock_guard<std::mutex> lock(mutex);
        for (const auto& event : events)
            delivered_ids.push_back(event.event_id());
        return result;
    }
    std::atomic<bool> available{false};
    std::mutex mutex;
    std::vector<std::string> delivered_ids;
};

class FilesOutboxTransactionTest : public ::testing::Test {
  protected:
    void SetUp() override {
        config_.host = "127.0.0.1";
        config_.port = 5433;
        config_.db_name = "securecloud_files";
        config_.db_user = "files_user";
        config_.db_password = securecloud::common::configuration::SecretString("files_dev_db_secret");
        config_.min_connections = 0;
        config_.max_connections = 8;
        config_.connect_timeout = std::chrono::seconds(2);
        config_.acquire_timeout = std::chrono::seconds(5);
        ASSERT_NE(config_.port, 5432) << "Tests must never connect to host PostgreSQL on port 5432";
        ASSERT_EQ(config_.port, 5433) << "Files outbox integration tests require container PostgreSQL 17 on port 5433";
        pool_ = std::make_shared<db::FilesDbConnectionPool>(config_);
        if (!pool_->ping(std::chrono::seconds(2)))
            GTEST_SKIP() << "PostgreSQL 17 at 127.0.0.1:5433 is unavailable";
        db::MigrationRunner migrations(pool_);
        const auto result = migrations.run_migrations();
        ASSERT_TRUE(result.success) << result.error_message;
        repository_ = std::make_shared<FilesOutboxRepository>(pool_);
        {
            advisory_lock_ = pool_->acquire();
            auto* connection = dynamic_cast<db::DefaultDbConnection*>(advisory_lock_.get());
            ASSERT_NE(connection, nullptr);
            pqxx::work tx(connection->native_handle());
            tx.exec("SELECT pg_advisory_lock(915015007::bigint)");
            tx.commit();
        }
        if (repository_->count_pending() != 0) {
            GTEST_SKIP() << "Files outbox integration DB has pending rows; refusing to process non-test events";
        }
    }

    void TearDown() override {
        cleanup(created_ids_);
        if (advisory_lock_) {
            if (auto* connection = dynamic_cast<db::DefaultDbConnection*>(advisory_lock_.get())) {
                try {
                    pqxx::work tx(connection->native_handle());
                    tx.exec("SELECT pg_advisory_unlock(915015007::bigint)");
                    tx.commit();
                } catch (...) {
                }
            }
            advisory_lock_ = db::PooledConnection{};
        }
        if (pool_) {
            pool_->drain();
            pool_->close();
        }
    }

    void cleanup(const std::vector<std::string>& ids) {
        if (!pool_ || ids.empty())
            return;
        auto lease = pool_->acquire();
        auto* connection = dynamic_cast<db::DefaultDbConnection*>(lease.get());
        if (!connection)
            return;
        pqxx::work tx(connection->native_handle());
        for (const auto& id : ids)
            tx.exec("DELETE FROM files_outbox WHERE event_id = $1", pqxx::params{id});
        tx.commit();
    }

    void track(const std::string& id) { created_ids_.push_back(id); }

    db::ConnectionPoolConfig config_;
    std::shared_ptr<db::FilesDbConnectionPool> pool_;
    std::shared_ptr<FilesOutboxRepository> repository_;
    db::PooledConnection advisory_lock_;
    std::vector<std::string> created_ids_;
};

TEST(FilesOutboxPreflightTest, StrictPort5432Protection) {
    db::ConnectionPoolConfig forbidden;
    forbidden.host = "127.0.0.1";
    forbidden.port = 5432;
    EXPECT_THROW((db::FilesDbConnectionPool(forbidden)), db::PortForbiddenException);
}

TEST_F(FilesOutboxTransactionTest, TransactionalStageCommitsAndRollbackLeavesNoPhantomRow) {
    auto committed = make_event();
    auto rolled_back = make_event();
    track(committed.event_id);
    track(rolled_back.event_id);
    auto lease = pool_->acquire();
    auto* connection = dynamic_cast<db::DefaultDbConnection*>(lease.get());
    ASSERT_NE(connection, nullptr);
    {
        pqxx::work tx(connection->native_handle());
        repository_->stage_event(committed, tx);
        tx.commit();
    }
    {
        pqxx::work tx(connection->native_handle());
        repository_->stage_event(rolled_back, tx);
        tx.abort();
    }
    EXPECT_TRUE(repository_->find_by_id(committed.event_id).has_value());
    EXPECT_FALSE(repository_->find_by_id(rolled_back.event_id).has_value());
    cleanup({committed.event_id, rolled_back.event_id});
}

TEST_F(FilesOutboxTransactionTest, FourWorkersLeaseOneThousandEventsWithoutDuplicates) {
    constexpr size_t k_event_count = 1000;
    std::vector<std::string> ids;
    ids.reserve(k_event_count);
    auto lease = pool_->acquire();
    auto* connection = dynamic_cast<db::DefaultDbConnection*>(lease.get());
    ASSERT_NE(connection, nullptr);
    {
        pqxx::work tx(connection->native_handle());
        for (size_t i = 0; i < k_event_count; ++i) {
            auto event = make_event();
            ids.push_back(event.event_id);
            track(event.event_id);
            repository_->stage_event(event, tx);
        }
        tx.commit();
    }
    std::mutex ids_mutex;
    std::unordered_set<std::string> seen;
    std::atomic<size_t> claimed{0};
    std::vector<std::thread> workers;
    for (size_t worker = 0; worker < 4; ++worker) {
        workers.emplace_back([&] {
            for (;;) {
                const auto batch = repository_->fetch_and_lease_pending_batch(25, std::chrono::seconds(60));
                if (batch.empty())
                    break;
                for (const auto& event : batch) {
                    bool inserted = false;
                    {
                        std::lock_guard<std::mutex> lock(ids_mutex);
                        inserted = seen.insert(event.event_id).second;
                    }
                    EXPECT_TRUE(inserted) << "duplicate lease " << event.event_id;
                    ++claimed;
                    repository_->mark_published(event.event_id);
                }
            }
        });
    }
    for (auto& worker : workers)
        worker.join();
    EXPECT_EQ(claimed.load(), k_event_count);
    EXPECT_EQ(seen.size(), k_event_count);
    cleanup(ids);
}

TEST_F(FilesOutboxTransactionTest, ReclaimsExpiredLeaseDrainsAfterOutageAndQuarantinesMalformedRows) {
    auto event = make_event();
    track(event.event_id);
    repository_->stage_event(event);
    {
        auto lease = pool_->acquire();
        auto* connection = dynamic_cast<db::DefaultDbConnection*>(lease.get());
        ASSERT_NE(connection, nullptr);
        pqxx::work tx(connection->native_handle());
        tx.exec("UPDATE files_outbox SET leased_until = NOW() - INTERVAL '1 minute' WHERE event_id = $1",
                pqxx::params{event.event_id});
        tx.commit();
    }
    const auto reclaimed = repository_->fetch_and_lease_pending_batch(1, std::chrono::seconds(30));
    ASSERT_EQ(reclaimed.size(), 1u);
    EXPECT_EQ(reclaimed.front().event_id, event.event_id);
    EXPECT_TRUE(repository_->record_transient_failure(event.event_id, "simulated outage"));
    const auto still_pending = repository_->find_by_id(event.event_id);
    ASSERT_TRUE(still_pending.has_value());
    EXPECT_EQ(still_pending->status, OutboxStatus::Pending);

    auto client = std::make_shared<ToggleAuditClient>();
    audit::FilesOutboxRelay relay(repository_, client);
    EXPECT_EQ(relay.poll_and_dispatch(1), 1u);
    const auto remains_pending = repository_->find_by_id(event.event_id);
    ASSERT_TRUE(remains_pending.has_value());
    EXPECT_EQ(remains_pending->status, OutboxStatus::Pending);
    client->available.store(true, std::memory_order_release);
    EXPECT_EQ(relay.poll_and_dispatch(1), 1u);
    const auto published = repository_->find_by_id(event.event_id);
    ASSERT_TRUE(published.has_value());
    EXPECT_EQ(published->status, OutboxStatus::Published);
    EXPECT_EQ(client->delivered_ids, std::vector<std::string>{event.event_id});

    auto poison = make_event();
    poison.event_type = "not-an-audit-event";
    track(poison.event_id);
    repository_->stage_event(poison);
    EXPECT_EQ(relay.poll_and_dispatch(1), 1u);
    const auto quarantined = repository_->find_by_id(poison.event_id);
    ASSERT_TRUE(quarantined.has_value());
    EXPECT_EQ(quarantined->status, OutboxStatus::Quarantined);

    {
        auto lease = pool_->acquire();
        auto* db_connection = dynamic_cast<db::DefaultDbConnection*>(lease.get());
        ASSERT_NE(db_connection, nullptr);
        pqxx::work tx(db_connection->native_handle());
        tx.exec("UPDATE files_outbox SET processed_at = NOW() - INTERVAL '8 days' WHERE event_id = $1",
                pqxx::params{event.event_id});
        tx.commit();
    }
    EXPECT_EQ(
        repository_->purge_published_older_than(std::chrono::system_clock::now() - std::chrono::hours(24 * 7), 10), 1u);
    cleanup({event.event_id, poison.event_id});
}
} // namespace
} // namespace securecloud::files::integration
