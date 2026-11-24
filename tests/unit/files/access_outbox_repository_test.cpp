#include "files/db/pqxx_compat.hpp"
#include "files/domain/file_access_entity.hpp"
#include "files/domain/file_entity.hpp"
#include "files/domain/files_outbox_entity.hpp"
#include "files/repository/file_access_repository.hpp"
#include "files/repository/file_repository.hpp"
#include "files/repository/files_outbox_repository.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::files {
namespace {

class AccessOutboxRepositoryTest : public ::testing::Test {
  protected:
    void SetUp() override {
        // Reset in-memory mock storage before each test case
        pqxx::MockStorage::instance().reset();
    }
};

FileEntity make_sample_file(std::string file_id, std::string owner_user_id) {
    FileEntity f;
    f.file_id = std::move(file_id);
    f.owner_user_id = std::move(owner_user_id);
    f.owner_device_id = "device-uuid-1";
    f.encrypted_size = 1048576;
    f.encryption_algorithm = "XChaCha20-Poly1305";
    f.status = FileStatus::Available;
    f.created_at = std::chrono::system_clock::now();
    f.updated_at = f.created_at;
    return f;
}

EncryptedFileMetadataEntity make_sample_metadata(std::string file_id) {
    EncryptedFileMetadataEntity m;
    m.file_id = std::move(file_id);
    m.encrypted_filename = {0x01, 0x02, 0x03, 0x04};
    m.metadata_nonce = {0xAA, 0xBB, 0xCC, 0xDD};
    m.metadata_tag = {0xEE, 0xFF, 0x00, 0x11};
    m.client_encryption_metadata_json = "{}";
    m.updated_at = std::chrono::system_clock::now();
    return m;
}

FileAccessEntity make_sample_grant(std::string access_id, std::string file_id, std::string grantee_user_id,
                                   FilePermission permission = FilePermission::Read,
                                   std::string granted_by = "owner-uuid-1") {
    FileAccessEntity a;
    a.access_id = std::move(access_id);
    a.file_id = std::move(file_id);
    a.grantee_user_id = std::move(grantee_user_id);
    a.permission = permission;
    a.granted_by = std::move(granted_by);
    a.granted_at = std::chrono::system_clock::now();
    return a;
}

FilesOutboxEntity make_sample_event(std::string event_id, std::optional<std::string> aggregate_id,
                                    std::string event_type = "FILE_UPLOAD_COMPLETED",
                                    std::string payload = "{\"file_id\":\"f-1\",\"bytes\":1024}") {
    FilesOutboxEntity e;
    e.event_id = std::move(event_id);
    e.aggregate_type = "FILE";
    e.aggregate_id = std::move(aggregate_id);
    e.event_type = std::move(event_type);
    e.payload_json = std::move(payload);
    e.status = OutboxStatus::Pending;
    e.retry_count = 0;
    e.created_at = std::chrono::system_clock::now();
    return e;
}

// ============================================================================
// FileAccessRepository Unit Tests
// ============================================================================

TEST_F(AccessOutboxRepositoryTest, OwnerHasImplicitAdminAccess) {
    FileRepository file_repo;
    FileAccessRepository access_repo;

    auto file = make_sample_file("file-100", "owner-user-1");
    auto meta = make_sample_metadata("file-100");

    {
        pqxx::work tx;
        file_repo.create_file(file, meta, tx);
        tx.commit();
    }

    // Owner should have Read, Write, and Admin access implicitly without any entry in file_access
    EXPECT_TRUE(access_repo.check_access("file-100", "owner-user-1", FilePermission::Read));
    EXPECT_TRUE(access_repo.check_access("file-100", "owner-user-1", FilePermission::Write));
    EXPECT_TRUE(access_repo.check_access("file-100", "owner-user-1", FilePermission::Admin));
}

TEST_F(AccessOutboxRepositoryTest, NonOwnerWithoutGrantReturnsFalse) {
    FileRepository file_repo;
    FileAccessRepository access_repo;

    auto file = make_sample_file("file-101", "owner-user-1");
    auto meta = make_sample_metadata("file-101");

    {
        pqxx::work tx;
        file_repo.create_file(file, meta, tx);
        tx.commit();
    }

    // Stranger with no grant has no access whatsoever
    EXPECT_FALSE(access_repo.check_access("file-101", "stranger-user", FilePermission::Read));
    EXPECT_FALSE(access_repo.check_access("file-101", "stranger-user", FilePermission::Write));
    EXPECT_FALSE(access_repo.check_access("file-101", "stranger-user", FilePermission::Admin));
}

TEST_F(AccessOutboxRepositoryTest, NonOwnerWithReadGrant) {
    FileRepository file_repo;
    FileAccessRepository access_repo;

    auto file = make_sample_file("file-102", "owner-user-1");
    auto meta = make_sample_metadata("file-102");

    {
        pqxx::work tx;
        file_repo.create_file(file, meta, tx);
        auto grant = make_sample_grant("acc-1", "file-102", "reader-user", FilePermission::Read);
        access_repo.grant_access(grant, tx);
        tx.commit();
    }

    // Read grant satisfies Read, but rejects Write and Admin
    EXPECT_TRUE(access_repo.check_access("file-102", "reader-user", FilePermission::Read));
    EXPECT_FALSE(access_repo.check_access("file-102", "reader-user", FilePermission::Write));
    EXPECT_FALSE(access_repo.check_access("file-102", "reader-user", FilePermission::Admin));
}

TEST_F(AccessOutboxRepositoryTest, NonOwnerWithWriteGrant) {
    FileRepository file_repo;
    FileAccessRepository access_repo;

    auto file = make_sample_file("file-103", "owner-user-1");
    auto meta = make_sample_metadata("file-103");

    {
        pqxx::work tx;
        file_repo.create_file(file, meta, tx);
        auto grant = make_sample_grant("acc-2", "file-103", "writer-user", FilePermission::Write);
        access_repo.grant_access(grant, tx);
        tx.commit();
    }

    // Write grant satisfies Read and Write, but rejects Admin
    EXPECT_TRUE(access_repo.check_access("file-103", "writer-user", FilePermission::Read));
    EXPECT_TRUE(access_repo.check_access("file-103", "writer-user", FilePermission::Write));
    EXPECT_FALSE(access_repo.check_access("file-103", "writer-user", FilePermission::Admin));
}

TEST_F(AccessOutboxRepositoryTest, NonOwnerWithAdminGrant) {
    FileRepository file_repo;
    FileAccessRepository access_repo;

    auto file = make_sample_file("file-104", "owner-user-1");
    auto meta = make_sample_metadata("file-104");

    {
        pqxx::work tx;
        file_repo.create_file(file, meta, tx);
        auto grant = make_sample_grant("acc-3", "file-104", "admin-delegate", FilePermission::Admin);
        access_repo.grant_access(grant, tx);
        tx.commit();
    }

    // Admin grant satisfies all permission levels
    EXPECT_TRUE(access_repo.check_access("file-104", "admin-delegate", FilePermission::Read));
    EXPECT_TRUE(access_repo.check_access("file-104", "admin-delegate", FilePermission::Write));
    EXPECT_TRUE(access_repo.check_access("file-104", "admin-delegate", FilePermission::Admin));
}

TEST_F(AccessOutboxRepositoryTest, RevokeAccessFailsSubsequentChecks) {
    FileRepository file_repo;
    FileAccessRepository access_repo;

    auto file = make_sample_file("file-105", "owner-user-1");
    auto meta = make_sample_metadata("file-105");

    {
        pqxx::work tx;
        file_repo.create_file(file, meta, tx);
        auto grant = make_sample_grant("acc-4", "file-105", "collab-user", FilePermission::Write);
        access_repo.grant_access(grant, tx);
        tx.commit();
    }

    EXPECT_TRUE(access_repo.check_access("file-105", "collab-user", FilePermission::Write));

    // Revoke access
    bool revoked = access_repo.revoke_access("file-105", "collab-user");
    EXPECT_TRUE(revoked);

    // After revocation, user has no access
    EXPECT_FALSE(access_repo.check_access("file-105", "collab-user", FilePermission::Read));
    EXPECT_FALSE(access_repo.check_access("file-105", "collab-user", FilePermission::Write));

    // Subsequent revocation on already revoked grant returns false
    EXPECT_FALSE(access_repo.revoke_access("file-105", "collab-user"));
}

TEST_F(AccessOutboxRepositoryTest, UpdateGrantPermissionAndClearRevocation) {
    FileRepository file_repo;
    FileAccessRepository access_repo;

    auto file = make_sample_file("file-106", "owner-user-1");
    auto meta = make_sample_metadata("file-106");

    {
        pqxx::work tx;
        file_repo.create_file(file, meta, tx);
        auto grant = make_sample_grant("acc-5", "file-106", "user-x", FilePermission::Read);
        access_repo.grant_access(grant, tx);
        tx.commit();
    }

    EXPECT_TRUE(access_repo.check_access("file-106", "user-x", FilePermission::Read));
    EXPECT_FALSE(access_repo.check_access("file-106", "user-x", FilePermission::Write));

    // Revoke
    EXPECT_TRUE(access_repo.revoke_access("file-106", "user-x"));
    EXPECT_FALSE(access_repo.check_access("file-106", "user-x", FilePermission::Read));

    // Re-grant with Write permission (clears revocation)
    auto upgraded_grant = make_sample_grant("acc-5", "file-106", "user-x", FilePermission::Write);
    access_repo.grant_access(upgraded_grant);

    EXPECT_TRUE(access_repo.check_access("file-106", "user-x", FilePermission::Read));
    EXPECT_TRUE(access_repo.check_access("file-106", "user-x", FilePermission::Write));
}

TEST_F(AccessOutboxRepositoryTest, ListGranteesReturnsOnlyActiveOrdered) {
    FileRepository file_repo;
    FileAccessRepository access_repo;

    auto file = make_sample_file("file-107", "owner-user-1");
    auto meta = make_sample_metadata("file-107");

    auto now = std::chrono::system_clock::now();

    {
        pqxx::work tx;
        file_repo.create_file(file, meta, tx);

        auto g1 = make_sample_grant("acc-1", "file-107", "user-1", FilePermission::Read);
        g1.granted_at = now - std::chrono::minutes(10);
        access_repo.grant_access(g1, tx);

        auto g2 = make_sample_grant("acc-2", "file-107", "user-2", FilePermission::Write);
        g2.granted_at = now - std::chrono::minutes(5);
        access_repo.grant_access(g2, tx);

        auto g3 = make_sample_grant("acc-3", "file-107", "user-3", FilePermission::Admin);
        g3.granted_at = now;
        access_repo.grant_access(g3, tx);

        tx.commit();
    }

    auto grantees = access_repo.list_grantees("file-107");
    ASSERT_EQ(grantees.size(), 3);
    EXPECT_EQ(grantees[0].grantee_user_id, "user-1");
    EXPECT_EQ(grantees[1].grantee_user_id, "user-2");
    EXPECT_EQ(grantees[2].grantee_user_id, "user-3");

    // Revoke user-2
    EXPECT_TRUE(access_repo.revoke_access("file-107", "user-2"));

    // list_grantees should now return only user-1 and user-3
    auto active_grantees = access_repo.list_grantees("file-107");
    ASSERT_EQ(active_grantees.size(), 2);
    EXPECT_EQ(active_grantees[0].grantee_user_id, "user-1");
    EXPECT_EQ(active_grantees[1].grantee_user_id, "user-3");
}

TEST_F(AccessOutboxRepositoryTest, FindGrantById) {
    FileAccessRepository access_repo;
    auto grant = make_sample_grant("acc-10", "file-108", "user-10", FilePermission::Admin);

    access_repo.grant_access(grant);

    auto found = access_repo.find_grant("file-108", "user-10");
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->access_id, "acc-10");
    EXPECT_EQ(found->permission, FilePermission::Admin);

    EXPECT_FALSE(access_repo.find_grant("file-108", "non-existent").has_value());
    EXPECT_FALSE(access_repo.find_grant("", "").has_value());
}

TEST_F(AccessOutboxRepositoryTest, FileAccessValidationFailures) {
    FileAccessRepository repo;
    FileAccessEntity invalid;

    EXPECT_THROW(repo.grant_access(invalid), RepositoryException);

    invalid.access_id = "acc-1";
    EXPECT_THROW(repo.grant_access(invalid), RepositoryException);

    invalid.file_id = "file-1";
    EXPECT_THROW(repo.grant_access(invalid), RepositoryException);

    invalid.grantee_user_id = "user-1";
    EXPECT_THROW(repo.grant_access(invalid), RepositoryException); // missing granted_by

    invalid.granted_by = "owner-1";
    EXPECT_NO_THROW(repo.grant_access(invalid));

    // check_access with empty ids fails closed (returns false)
    EXPECT_FALSE(repo.check_access("", "user-1", FilePermission::Read));
    EXPECT_FALSE(repo.check_access("file-1", "", FilePermission::Read));
    EXPECT_FALSE(repo.revoke_access("", ""));
}

// ============================================================================
// FilesOutboxRepository Unit Tests
// ============================================================================

TEST_F(AccessOutboxRepositoryTest, StageAndFetchPendingEvents) {
    FilesOutboxRepository outbox_repo;

    auto now = std::chrono::system_clock::now();
    auto e1 = make_sample_event("evt-1", "file-1", "FILE_CREATED");
    e1.created_at = now - std::chrono::minutes(2);

    auto e2 = make_sample_event("evt-2", "file-1", "FILE_UPLOAD_COMPLETED");
    e2.created_at = now - std::chrono::minutes(1);

    auto e3 = make_sample_event("evt-3", "file-2", "FILE_DELETED");
    e3.created_at = now;

    {
        pqxx::work tx;
        outbox_repo.stage_event(e1, tx);
        outbox_repo.stage_event(e2, tx);
        outbox_repo.stage_event(e3, tx);
        tx.commit();
    }

    // First fetch respects limit=2 and leases the first two events
    auto limited = outbox_repo.fetch_pending_events(2);
    ASSERT_EQ(limited.size(), 2);
    EXPECT_EQ(limited[0].event_id, "evt-1");
    EXPECT_EQ(limited[1].event_id, "evt-2");

    // Subsequent fetch returns only the remaining unleased event
    auto remaining = outbox_repo.fetch_pending_events(10);
    ASSERT_EQ(remaining.size(), 1);
    EXPECT_EQ(remaining[0].event_id, "evt-3");
}

TEST_F(AccessOutboxRepositoryTest, StageEventWithNullAggregateIdAndSeverity) {
    FilesOutboxRepository outbox_repo;
    auto e = make_sample_event("evt-sys-1", std::nullopt, "FILES_SECURITY_ALERT");
    e.aggregate_type = "SYSTEM";
    e.severity = OutboxSeverity::Critical;

    outbox_repo.stage_event(e);

    auto found = outbox_repo.find_by_id("evt-sys-1");
    ASSERT_TRUE(found.has_value());
    EXPECT_FALSE(found->aggregate_id.has_value());
    EXPECT_EQ(found->severity, OutboxSeverity::Critical);
    EXPECT_EQ(found->status, OutboxStatus::Pending);
}

TEST_F(AccessOutboxRepositoryTest, FetchAndLeasePendingBatchDisjointAndReacquiresAfterExpiry) {
    FilesOutboxRepository outbox_repo;

    auto now = std::chrono::system_clock::now();
    auto e1 = make_sample_event("evt-lease-1", "file-1");
    e1.created_at = now - std::chrono::seconds(30);
    auto e2 = make_sample_event("evt-lease-2", "file-2");
    e2.created_at = now - std::chrono::seconds(20);
    auto e3 = make_sample_event("evt-lease-3", "file-3");
    e3.created_at = now - std::chrono::seconds(10);

    outbox_repo.stage_event(e1);
    outbox_repo.stage_event(e2);
    outbox_repo.stage_event(e3);

    // First worker leases 2 events with a 30-second lease
    auto batch1 = outbox_repo.fetch_and_lease_pending_batch(2, std::chrono::seconds{30});
    ASSERT_EQ(batch1.size(), 2);
    EXPECT_EQ(batch1[0].event_id, "evt-lease-1");
    EXPECT_EQ(batch1[1].event_id, "evt-lease-2");
    EXPECT_TRUE(batch1[0].leased_until.has_value());
    EXPECT_TRUE(batch1[1].leased_until.has_value());
    EXPECT_EQ(batch1[0].status, OutboxStatus::Pending);

    // Second concurrent worker immediately fetches with a 1-second lease: must receive only disjoint evt-lease-3
    auto batch2 = outbox_repo.fetch_and_lease_pending_batch(10, std::chrono::seconds{1});
    ASSERT_EQ(batch2.size(), 1);
    EXPECT_EQ(batch2[0].event_id, "evt-lease-3");

    // Once batch2's 1-second lease expires, evt-lease-3 can be leased again while batch1 remains leased
    std::this_thread::sleep_for(std::chrono::milliseconds{1100});
    auto batch3 = outbox_repo.fetch_and_lease_pending_batch(10, std::chrono::seconds{30});
    ASSERT_EQ(batch3.size(), 1);
    EXPECT_EQ(batch3[0].event_id, "evt-lease-3");
}

TEST_F(AccessOutboxRepositoryTest, RecordTransientFailureKeepsPendingAndClearsLease) {
    FilesOutboxRepository outbox_repo;
    auto e = make_sample_event("evt-transient", "file-transient");
    outbox_repo.stage_event(e);

    auto leased = outbox_repo.fetch_and_lease_pending_batch(1, std::chrono::seconds{60});
    ASSERT_EQ(leased.size(), 1);
    ASSERT_TRUE(leased[0].leased_until.has_value());

    // Record transient failure: status remains PENDING, retry_count increments, lease cleared
    EXPECT_TRUE(outbox_repo.record_transient_failure("evt-transient", "gRPC UNAVAILABLE: deadline exceeded"));

    auto found = outbox_repo.find_by_id("evt-transient");
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->status, OutboxStatus::Pending);
    EXPECT_EQ(found->retry_count, 1);
    EXPECT_FALSE(found->leased_until.has_value());
    ASSERT_TRUE(found->last_error.has_value());
    EXPECT_EQ(*found->last_error, "gRPC UNAVAILABLE: deadline exceeded");

    // Because lease was cleared and status is still PENDING, it is immediately re-leasable
    auto reacquired = outbox_repo.fetch_and_lease_pending_batch(1, std::chrono::seconds{30});
    ASSERT_EQ(reacquired.size(), 1);
    EXPECT_EQ(reacquired[0].event_id, "evt-transient");

    EXPECT_FALSE(outbox_repo.record_transient_failure("non-existent", "err"));
}

TEST_F(AccessOutboxRepositoryTest, MarkQuarantinedExcludesFromPendingAndLeasing) {
    FilesOutboxRepository outbox_repo;
    auto e = make_sample_event("evt-poison", "file-poison");
    outbox_repo.stage_event(e);

    auto leased = outbox_repo.fetch_and_lease_pending_batch(1, std::chrono::seconds{30});
    ASSERT_EQ(leased.size(), 1);

    EXPECT_TRUE(outbox_repo.mark_quarantined("evt-poison", "Max retries exceeded: invalid schema"));

    auto found = outbox_repo.find_by_id("evt-poison");
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->status, OutboxStatus::Quarantined);
    EXPECT_FALSE(found->leased_until.has_value());
    ASSERT_TRUE(found->last_error.has_value());
    EXPECT_EQ(*found->last_error, "Max retries exceeded: invalid schema");

    // Quarantined events must never be returned as pending or counted in pending backlog
    EXPECT_TRUE(outbox_repo.fetch_pending_events(10).empty());
    EXPECT_TRUE(outbox_repo.fetch_and_lease_pending_batch(10, std::chrono::seconds{30}).empty());
    EXPECT_EQ(outbox_repo.count_pending(), 0);

    EXPECT_FALSE(outbox_repo.mark_quarantined("non-existent", "err"));
}

TEST_F(AccessOutboxRepositoryTest, PurgePublishedOlderThanDeletesOnlyExpiredPublishedEvents) {
    FilesOutboxRepository outbox_repo;

    auto now = std::chrono::system_clock::now();
    auto old_pub = make_sample_event("evt-old-pub", "file-1");
    auto recent_pub = make_sample_event("evt-recent-pub", "file-2");
    auto old_pending = make_sample_event("evt-old-pending", "file-3");
    old_pending.created_at = now - std::chrono::hours(48);

    outbox_repo.stage_event(old_pub);
    outbox_repo.stage_event(recent_pub);
    outbox_repo.stage_event(old_pending);

    ASSERT_TRUE(outbox_repo.mark_published("evt-old-pub"));
    std::this_thread::sleep_for(std::chrono::milliseconds{1100});
    auto cutoff = std::chrono::system_clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds{1100});
    ASSERT_TRUE(outbox_repo.mark_published("evt-recent-pub"));

    auto purged_count = outbox_repo.purge_published_older_than(cutoff, 100);
    EXPECT_EQ(purged_count, 1u);

    EXPECT_FALSE(outbox_repo.find_by_id("evt-old-pub").has_value());
    EXPECT_TRUE(outbox_repo.find_by_id("evt-recent-pub").has_value());
    EXPECT_TRUE(outbox_repo.find_by_id("evt-old-pending").has_value());
}

TEST_F(AccessOutboxRepositoryTest, CountPendingAndOldestPendingAgeSeconds) {
    FilesOutboxRepository outbox_repo;

    EXPECT_EQ(outbox_repo.count_pending(), 0);
    EXPECT_DOUBLE_EQ(outbox_repo.oldest_pending_age_seconds(), 0.0);

    auto now = std::chrono::system_clock::now();
    auto older = make_sample_event("evt-age-1", "file-1");
    older.created_at = now - std::chrono::seconds(120);

    auto newer = make_sample_event("evt-age-2", "file-2");
    newer.created_at = now - std::chrono::seconds(20);

    outbox_repo.stage_event(older);
    outbox_repo.stage_event(newer);

    EXPECT_EQ(outbox_repo.count_pending(), 2);
    double age1 = outbox_repo.oldest_pending_age_seconds();
    EXPECT_GE(age1, 110.0);

    // Once the oldest event is published, age reflects the remaining pending event
    ASSERT_TRUE(outbox_repo.mark_published("evt-age-1"));
    EXPECT_EQ(outbox_repo.count_pending(), 1);
    double age2 = outbox_repo.oldest_pending_age_seconds();
    EXPECT_LT(age2, 60.0);
}

TEST_F(AccessOutboxRepositoryTest, MarkPublishedRemovesFromPending) {
    FilesOutboxRepository outbox_repo;
    auto e = make_sample_event("evt-10", "file-10");

    outbox_repo.stage_event(e);

    auto pending_before = outbox_repo.fetch_pending_events(10);
    ASSERT_EQ(pending_before.size(), 1);
    EXPECT_EQ(pending_before[0].status, OutboxStatus::Pending);

    // Mark published
    EXPECT_TRUE(outbox_repo.mark_published("evt-10"));

    // Should no longer appear in pending batch
    auto pending_after = outbox_repo.fetch_pending_events(10);
    EXPECT_TRUE(pending_after.empty());

    // Should exist with Published status and processed timestamp
    auto found = outbox_repo.find_by_id("evt-10");
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->status, OutboxStatus::Published);
    EXPECT_TRUE(found->processed_at.has_value());
}

TEST_F(AccessOutboxRepositoryTest, MarkFailedIncrementsRetryCount) {
    FilesOutboxRepository outbox_repo;
    auto e = make_sample_event("evt-20", "file-20");

    outbox_repo.stage_event(e);

    EXPECT_TRUE(outbox_repo.mark_failed("evt-20"));

    auto found = outbox_repo.find_by_id("evt-20");
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->status, OutboxStatus::Failed);
    EXPECT_EQ(found->retry_count, 1);

    // Increment again
    EXPECT_TRUE(outbox_repo.mark_failed("evt-20"));
    auto found2 = outbox_repo.find_by_id("evt-20");
    ASSERT_TRUE(found2.has_value());
    EXPECT_EQ(found2->retry_count, 2);

    // Non-existent event returns false
    EXPECT_FALSE(outbox_repo.mark_failed("non-existent"));
    EXPECT_FALSE(outbox_repo.mark_published("non-existent"));
}

TEST_F(AccessOutboxRepositoryTest, OutboxTransactionRollbackLeavesNoOrphanEvents) {
    FilesOutboxRepository outbox_repo;
    auto e = make_sample_event("evt-abort", "file-abort");

    {
        pqxx::work tx;
        outbox_repo.stage_event(e, tx);
        tx.abort(); // Transaction aborted
    }

    EXPECT_TRUE(outbox_repo.fetch_pending_events(10).empty());
    EXPECT_FALSE(outbox_repo.find_by_id("evt-abort").has_value());
}

TEST_F(AccessOutboxRepositoryTest, OutboxValidationFailures) {
    FilesOutboxRepository repo;
    FilesOutboxEntity invalid;

    EXPECT_THROW(repo.stage_event(invalid), RepositoryException);

    invalid.event_id = "evt-1";
    EXPECT_THROW(repo.stage_event(invalid), RepositoryException);

    invalid.event_type = "TYPE";
    EXPECT_THROW(repo.stage_event(invalid), RepositoryException); // missing payload_json

    // aggregate_id is nullable since V002
    invalid.payload_json = "{}";
    EXPECT_NO_THROW(repo.stage_event(invalid));
}

TEST_F(AccessOutboxRepositoryTest, AtomicDomainStateAndOutboxPersistence) {
    FileRepository file_repo;
    FileAccessRepository access_repo;
    FilesOutboxRepository outbox_repo;

    auto file = make_sample_file("file-atomic", "owner-user");
    auto meta = make_sample_metadata("file-atomic");
    auto grant = make_sample_grant("acc-atomic", "file-atomic", "user-collab", FilePermission::Write);
    auto event = make_sample_event("evt-atomic", "file-atomic", "FILE_CREATED");

    // All entities committed together in a single atomic transaction
    {
        pqxx::work tx;
        file_repo.create_file(file, meta, tx);
        access_repo.grant_access(grant, tx);
        outbox_repo.stage_event(event, tx);
        tx.commit();
    }

    // Verify all states exist and are queryable
    EXPECT_TRUE(file_repo.find_by_id("file-atomic").has_value());
    EXPECT_TRUE(access_repo.check_access("file-atomic", "owner-user", FilePermission::Admin));
    EXPECT_TRUE(access_repo.check_access("file-atomic", "user-collab", FilePermission::Write));
    EXPECT_TRUE(outbox_repo.find_by_id("evt-atomic").has_value());

    auto pending = outbox_repo.fetch_pending_events(10);
    ASSERT_EQ(pending.size(), 1);
    EXPECT_EQ(pending[0].event_id, "evt-atomic");
}

TEST_F(AccessOutboxRepositoryTest, RedactsSensitiveSecretsAndFilenamesInDiagnosticReasons) {
    FilesOutboxRepository outbox_repo;
    auto e1 = make_sample_event("evt-redact-1", "file-1");
    auto e2 = make_sample_event("evt-redact-2", "file-2");
    outbox_repo.stage_event(e1);
    outbox_repo.stage_event(e2);

    EXPECT_TRUE(outbox_repo.record_transient_failure("evt-redact-1", "failed with Bearer super-secret-jwt-token"));
    auto r1 = outbox_repo.find_by_id("evt-redact-1");
    ASSERT_TRUE(r1.has_value());
    ASSERT_TRUE(r1->last_error.has_value());
    EXPECT_EQ(*r1->last_error, "[REDACTED_SENSITIVE_DATA]");

    EXPECT_TRUE(outbox_repo.record_transient_failure("evt-redact-1", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"));
    r1 = outbox_repo.find_by_id("evt-redact-1");
    ASSERT_TRUE(r1.has_value());
    ASSERT_TRUE(r1->last_error.has_value());
    EXPECT_EQ(*r1->last_error, "[REDACTED_SENSITIVE_DATA]");

    EXPECT_TRUE(
        outbox_repo.mark_quarantined("evt-redact-2", "bad /var/tmp/report.pdf with -----BEGIN PRIVATE KEY-----"));
    const auto r2 = outbox_repo.find_by_id("evt-redact-2");
    ASSERT_TRUE(r2.has_value());
    ASSERT_TRUE(r2->last_error.has_value());
    EXPECT_EQ(*r2->last_error, "[REDACTED_SENSITIVE_DATA]");
}

} // namespace
} // namespace securecloud::files
