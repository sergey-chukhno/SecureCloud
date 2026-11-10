#include "audit/bounded_memory_pending_store.hpp"
#include "audit/file_spool_pending_store.hpp"
#include "audit/gateway_audit_spool_config.hpp"
#include "domain/event_id.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

namespace securecloud::gateway::audit {

class PendingStoreTest : public ::testing::Test {
  protected:
    void SetUp() override {
        test_dir_ = (std::filesystem::temp_directory_path() / "securecloud_test_spool").string();
        std::error_code ec;
        std::filesystem::remove_all(test_dir_, ec);
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(test_dir_, ec);
    }

    std::string test_dir_;
};

// =============================================================================
// BoundedMemoryPendingStore Tests
// =============================================================================

TEST_F(PendingStoreTest, BoundedMemoryStoreDurability) {
    BoundedMemoryPendingStore store(100, 1024 * 1024);
    EXPECT_EQ(store.durability(), StoreDurability::NonDurable);
    EXPECT_NE(store.durability(), StoreDurability::DurableAfterSync);
}

TEST_F(PendingStoreTest, BoundedMemoryStoreAppendAndClaim) {
    BoundedMemoryPendingStore store(10, 10240);

    PendingRecord rec1;
    rec1.event_id = securecloud::audit::domain::EventId::generate_v7();
    rec1.proto_bytes = {0x01, 0x02, 0x03, 0x04};

    PendingRecord rec2;
    rec2.event_id = securecloud::audit::domain::EventId::generate_v7();
    rec2.proto_bytes = {0x05, 0x06, 0x07, 0x08};

    EXPECT_EQ(store.append(rec1), AdmissionResult::AcceptedNonDurable);
    EXPECT_EQ(store.append(rec2), AdmissionResult::AcceptedNonDurable);

    auto batch = store.claim_batch(1);
    ASSERT_EQ(batch.size(), 1);
    EXPECT_EQ(batch[0].event_id, rec1.event_id);
    EXPECT_EQ(batch[0].attempt_count, 1);

    auto stats = store.stats();
    EXPECT_EQ(stats.total_records, 2);
    EXPECT_EQ(stats.claimed_records, 1);

    const securecloud::audit::domain::EventId ids[] = {rec1.event_id};
    store.mark_delivered(ids);

    stats = store.stats();
    EXPECT_EQ(stats.total_records, 1);
    EXPECT_EQ(stats.claimed_records, 0);
}

TEST_F(PendingStoreTest, BoundedMemoryStoreEvictsOldestWhenFull) {
    // Capacity configured for exactly 2 records
    BoundedMemoryPendingStore store(2, 10240);

    PendingRecord rec1;
    rec1.event_id = securecloud::audit::domain::EventId::generate_v7();
    rec1.proto_bytes = {0x11};

    PendingRecord rec2;
    rec2.event_id = securecloud::audit::domain::EventId::generate_v7();
    rec2.proto_bytes = {0x22};

    PendingRecord rec3;
    rec3.event_id = securecloud::audit::domain::EventId::generate_v7();
    rec3.proto_bytes = {0x33};

    EXPECT_EQ(store.append(rec1), AdmissionResult::AcceptedNonDurable);
    EXPECT_EQ(store.append(rec2), AdmissionResult::AcceptedNonDurable);
    // 3rd record forces eviction of rec1
    EXPECT_EQ(store.append(rec3), AdmissionResult::AcceptedNonDurable);

    auto stats = store.stats();
    EXPECT_EQ(stats.dropped_records, 1);

    auto batch = store.claim_batch(10);
    ASSERT_EQ(batch.size(), 2);
    EXPECT_EQ(batch[0].event_id, rec2.event_id);
    EXPECT_EQ(batch[1].event_id, rec3.event_id);
}

TEST_F(PendingStoreTest, BoundedMemoryStoreReleaseAndRetry) {
    BoundedMemoryPendingStore store(10, 10240);

    PendingRecord rec;
    rec.event_id = securecloud::audit::domain::EventId::generate_v7();
    rec.proto_bytes = {0xAA, 0xBB};

    EXPECT_EQ(store.append(rec), AdmissionResult::AcceptedNonDurable);

    auto batch = store.claim_batch(1);
    ASSERT_EQ(batch.size(), 1);

    const securecloud::audit::domain::EventId ids[] = {rec.event_id};
    store.release(ids);

    auto retry_batch = store.claim_batch(1);
    ASSERT_EQ(retry_batch.size(), 1);
    EXPECT_EQ(retry_batch[0].event_id, rec.event_id);
    EXPECT_EQ(retry_batch[0].attempt_count, 2);
}

TEST_F(PendingStoreTest, BoundedMemoryStoreMarkTerminal) {
    BoundedMemoryPendingStore store(10, 10240);

    PendingRecord rec;
    rec.event_id = securecloud::audit::domain::EventId::generate_v7();
    rec.proto_bytes = {0xDE, 0xAD};

    EXPECT_EQ(store.append(rec), AdmissionResult::AcceptedNonDurable);
    auto batch = store.claim_batch(1);
    ASSERT_EQ(batch.size(), 1);

    store.mark_terminal(rec.event_id, TerminalReason::ValidationFailed);

    auto stats = store.stats();
    EXPECT_EQ(stats.unrecoverable_records, 1);
    EXPECT_EQ(stats.claimed_records, 0);
    EXPECT_EQ(stats.total_records, 0);
}

// =============================================================================
// FileSpoolPendingStore Tests
// =============================================================================

TEST_F(PendingStoreTest, FileSpoolStoreDurability) {
    GatewayAuditSpoolConfig config;
    config.spool_directory = test_dir_;

    FileSpoolPendingStore store(config);
    EXPECT_EQ(store.durability(), StoreDurability::DurableAfterSync);
    EXPECT_TRUE(store.is_available());
}

TEST_F(PendingStoreTest, FileSpoolStoreGroupCommitAndRecovery) {
    GatewayAuditSpoolConfig config;
    config.spool_directory = test_dir_;
    config.group_commit_interval_ms = 5;

    const auto id1 = securecloud::audit::domain::EventId::generate_v7();
    const auto id2 = securecloud::audit::domain::EventId::generate_v7();

    {
        FileSpoolPendingStore store(config);
        EXPECT_TRUE(store.is_available());

        PendingRecord rec1;
        rec1.event_id = id1;
        rec1.proto_bytes = {0x10, 0x20, 0x30};

        PendingRecord rec2;
        rec2.event_id = id2;
        rec2.proto_bytes = {0x40, 0x50, 0x60};

        EXPECT_EQ(store.append(rec1), AdmissionResult::AcceptedPendingSync);
        EXPECT_EQ(store.append(rec2), AdmissionResult::AcceptedPendingSync);

        // Wait for worker thread group commit and fsync
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // Restart store from disk and verify exact recovery
    {
        FileSpoolPendingStore store_recovered(config);
        EXPECT_TRUE(store_recovered.is_available());

        auto batch = store_recovered.claim_batch(10);
        ASSERT_EQ(batch.size(), 2);
        EXPECT_EQ(batch[0].event_id, id1);
        EXPECT_EQ(batch[0].proto_bytes, (std::vector<uint8_t>{0x10, 0x20, 0x30}));
        EXPECT_EQ(batch[1].event_id, id2);
        EXPECT_EQ(batch[1].proto_bytes, (std::vector<uint8_t>{0x40, 0x50, 0x60}));
    }
}

TEST_F(PendingStoreTest, FileSpoolStoreTornTailTruncation) {
    GatewayAuditSpoolConfig config;
    config.spool_directory = test_dir_;
    config.group_commit_interval_ms = 5;

    const auto id1 = securecloud::audit::domain::EventId::generate_v7();

    {
        FileSpoolPendingStore store(config);
        PendingRecord rec1;
        rec1.event_id = id1;
        rec1.proto_bytes = {0x01, 0x02, 0x03, 0x04};
        EXPECT_EQ(store.append(rec1), AdmissionResult::AcceptedPendingSync);

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // Append corrupted torn tail bytes to spool.wal
    const auto wal_path = std::filesystem::path(test_dir_) / "spool.wal";
    {
        std::ofstream wal_file(wal_path, std::ios::binary | std::ios::app);
        const uint8_t garbage_bytes[] = {0x53, 0x43, 0x57, 0x41, 0x99, 0x99, 0x00, 0x00, 0xFF, 0xFF};
        wal_file.write(reinterpret_cast<const char*>(garbage_bytes), sizeof(garbage_bytes));
    }

    // Recover store; valid record rec1 is recovered, torn tail is truncated
    {
        FileSpoolPendingStore store_recovered(config);
        EXPECT_TRUE(store_recovered.is_available());

        auto batch = store_recovered.claim_batch(10);
        ASSERT_EQ(batch.size(), 1);
        EXPECT_EQ(batch[0].event_id, id1);

        auto stats = store_recovered.stats();
        EXPECT_GE(stats.unrecoverable_records, 1);
    }
}

TEST_F(PendingStoreTest, FileSpoolStoreCapEnforcement) {
    GatewayAuditSpoolConfig config;
    config.spool_directory = test_dir_;
    config.max_spool_records = 2;
    config.group_commit_interval_ms = 100;

    FileSpoolPendingStore store(config);

    PendingRecord rec1;
    rec1.event_id = securecloud::audit::domain::EventId::generate_v7();
    rec1.proto_bytes = {0x01};

    PendingRecord rec2;
    rec2.event_id = securecloud::audit::domain::EventId::generate_v7();
    rec2.proto_bytes = {0x02};

    PendingRecord rec3;
    rec3.event_id = securecloud::audit::domain::EventId::generate_v7();
    rec3.proto_bytes = {0x03};

    EXPECT_EQ(store.append(rec1), AdmissionResult::AcceptedPendingSync);
    EXPECT_EQ(store.append(rec2), AdmissionResult::AcceptedPendingSync);
    // Exceeds max_spool_records limit
    EXPECT_EQ(store.append(rec3), AdmissionResult::RejectedFull);

    auto stats = store.stats();
    EXPECT_EQ(stats.dropped_records, 1);
}

TEST_F(PendingStoreTest, FileSpoolStoreReleaseAndMarkTerminal) {
    GatewayAuditSpoolConfig config;
    config.spool_directory = test_dir_;
    config.group_commit_interval_ms = 5;

    const auto id = securecloud::audit::domain::EventId::generate_v7();

    {
        FileSpoolPendingStore store(config);
        PendingRecord rec;
        rec.event_id = id;
        rec.proto_bytes = {0xAA};
        EXPECT_EQ(store.append(rec), AdmissionResult::AcceptedPendingSync);

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        auto batch = store.claim_batch(1);
        ASSERT_EQ(batch.size(), 1);

        const securecloud::audit::domain::EventId ids[] = {id};
        store.release(ids);

        auto retry_batch = store.claim_batch(1);
        ASSERT_EQ(retry_batch.size(), 1);

        store.mark_terminal(id, TerminalReason::MaxRetriesExceeded);

        auto stats = store.stats();
        EXPECT_EQ(stats.unrecoverable_records, 1);
        EXPECT_EQ(stats.claimed_records, 0);
    }
}

} // namespace securecloud::gateway::audit
