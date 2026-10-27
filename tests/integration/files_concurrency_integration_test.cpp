#include "files/concurrency/concurrency_bulkhead.hpp"
#include "files/concurrency/memory_buffer_tracker.hpp"
#include "files/concurrency/resource_config.hpp"
#include "files/service/files_service_impl.hpp"
#include "files/storage/bounded_storage_engine.hpp"
#include "securecloud/files/v1/files.grpc.pb.h"
#include "securecloud/files/v1/files.pb.h"

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef DeleteFile
#undef DeleteFile
#endif
#endif

namespace securecloud::files {
namespace {

using service::FilesServiceDependencies;
using service::FilesServiceImpl;
using service::IStorageEngine;
using storage::BoundedStorageEngine;
using storage::StorageCapacityExhaustedException;

class TestAuthPropertyIterator : public grpc::AuthPropertyIterator {
  public:
    TestAuthPropertyIterator() = default;
};

// Mock peer auth context
class TestAuthContext : public grpc::AuthContext {
  public:
    explicit TestAuthContext(bool is_authenticated) : is_authenticated_(is_authenticated) {}

    [[nodiscard]] bool IsPeerAuthenticated() const override { return is_authenticated_; }
    [[nodiscard]] std::string GetPeerIdentityPropertyName() const override { return "x509_subject_alternative_name"; }
    [[nodiscard]] std::vector<grpc::string_ref> GetPeerIdentity() const override {
        return {grpc::string_ref("DNS:gateway")};
    }
    [[nodiscard]] std::vector<grpc::string_ref> FindPropertyValues(const std::string& name) const override {
        if (name == "x509_subject_alternative_name") {
            return {grpc::string_ref("DNS:gateway")};
        }
        return {};
    }
    [[nodiscard]] grpc::AuthPropertyIterator begin() const override { return TestAuthPropertyIterator{}; }
    [[nodiscard]] grpc::AuthPropertyIterator end() const override { return TestAuthPropertyIterator{}; }
    void AddProperty(const std::string&, const grpc::string_ref&) override {}
    bool SetPeerIdentityPropertyName(const std::string&) override { return false; }

  private:
    bool is_authenticated_;
};

// Mock Storage Engine with observable concurrent operations
class MockStorageEngine : public service::IStorageEngine {
  public:
    std::atomic<size_t> active_ops{0};
    std::atomic<size_t> max_concurrent_ops{0};
    std::chrono::milliseconds artificial_delay{0};

    bool put_chunk(const std::string&, uint32_t, std::string_view, const std::string&) override {
        record_enter();
        if (artificial_delay.count() > 0)
            std::this_thread::sleep_for(artificial_delay);
        record_exit();
        return true;
    }

    std::optional<std::string> get_chunk(const std::string&, uint32_t) override {
        record_enter();
        if (artificial_delay.count() > 0)
            std::this_thread::sleep_for(artificial_delay);
        record_exit();
        return "mock_encrypted_chunk_bytes";
    }

    bool delete_chunk(const std::string&, uint32_t) override {
        record_enter();
        if (artificial_delay.count() > 0)
            std::this_thread::sleep_for(artificial_delay);
        record_exit();
        return true;
    }

    bool put_file_object(const std::string&, uint32_t, std::string_view, const std::string&) override {
        record_enter();
        if (artificial_delay.count() > 0)
            std::this_thread::sleep_for(artificial_delay);
        record_exit();
        return true;
    }

    std::optional<std::string> get_file_object(const std::string&, uint32_t,
                                               std::optional<storage::ByteRange>) override {
        record_enter();
        if (artificial_delay.count() > 0)
            std::this_thread::sleep_for(artificial_delay);
        record_exit();
        return "mock_file_object_bytes";
    }

    bool delete_file_objects(const std::string&) override {
        record_enter();
        if (artificial_delay.count() > 0)
            std::this_thread::sleep_for(artificial_delay);
        record_exit();
        return true;
    }

    bool delete_transfer_chunks(const std::string&) override {
        record_enter();
        if (artificial_delay.count() > 0)
            std::this_thread::sleep_for(artificial_delay);
        record_exit();
        return true;
    }

  private:
    void record_enter() {
        size_t current = ++active_ops;
        size_t prev = max_concurrent_ops.load();
        while (current > prev && !max_concurrent_ops.compare_exchange_weak(prev, current)) {
        }
    }

    void record_exit() { --active_ops; }
};

// ============================================================================
// TC1: Bulkhead Domain Isolation (Upload Saturation Does Not Starve Metadata)
// ============================================================================
TEST(FilesConcurrencyIntegrationTest, BulkheadDomainIsolationUnderUploadSaturation) {
    auto metadata_bulkhead = ConcurrencyBulkhead::create("metadata", 10, std::chrono::milliseconds(500));
    auto upload_bulkhead = ConcurrencyBulkhead::create("upload", 2, std::chrono::milliseconds(50));
    auto download_bulkhead = ConcurrencyBulkhead::create("download", 10, std::chrono::milliseconds(500));

    FilesServiceDependencies deps{.metadata_bulkhead = metadata_bulkhead,
                                  .upload_bulkhead = upload_bulkhead,
                                  .download_bulkhead = download_bulkhead};
    FilesServiceImpl service(deps, "gateway");

    // Completely saturate upload bulkhead
    auto u1 = upload_bulkhead->try_acquire();
    auto u2 = upload_bulkhead->try_acquire();
    ASSERT_TRUE(u1.holds_permit());
    ASSERT_TRUE(u2.holds_permit());
    EXPECT_EQ(upload_bulkhead->available_permits(), 0);

    TestAuthContext gateway_ctx(true);

    // Verify upload request is rejected with RESOURCE_EXHAUSTED
    v1::UploadChunkRequest up_req;
    up_req.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    up_req.set_chunk_index(0);
    up_req.set_chunk_size_bytes(64);
    up_req.set_encrypted_data(std::string(64, 'U'));
    v1::UploadChunkResponse up_resp;

    auto up_status = service.UploadChunk(&gateway_ctx, &up_req, &up_resp);
    EXPECT_EQ(up_status.error_code(), grpc::StatusCode::RESOURCE_EXHAUSTED);

    // Metadata domain MUST remain unaffected and successfully acquire permit
    v1::CancelFileUploadRequest meta_req;
    meta_req.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    v1::CancelFileUploadResponse meta_resp;

    // Call goes past metadata bulkhead (fails later at session manager since not configured, NOT at bulkhead)
    auto meta_status = service.CancelFileUpload(&gateway_ctx, &meta_req, &meta_resp);
    EXPECT_NE(meta_status.error_code(), grpc::StatusCode::RESOURCE_EXHAUSTED);
}

// ============================================================================
// TC2: Saturated Download Domain Does Not Degrade Metadata Operations
// ============================================================================
TEST(FilesConcurrencyIntegrationTest, SaturatedDownloadDomainDoesNotDegradeMetadata) {
    auto metadata_bulkhead = ConcurrencyBulkhead::create("metadata", 10, std::chrono::milliseconds(500));
    auto download_bulkhead = ConcurrencyBulkhead::create("download", 1, std::chrono::milliseconds(50));

    FilesServiceDependencies deps{.metadata_bulkhead = metadata_bulkhead, .download_bulkhead = download_bulkhead};
    FilesServiceImpl service(deps, "gateway");

    // Saturate download domain
    auto d1 = download_bulkhead->try_acquire();
    ASSERT_TRUE(d1.holds_permit());

    TestAuthContext gateway_ctx(true);

    v1::DownloadChunkRequest dl_req;
    dl_req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    dl_req.set_chunk_index(0);
    v1::DownloadChunkResponse dl_resp;

    auto dl_status = service.DownloadChunk(&gateway_ctx, &dl_req, &dl_resp);
    EXPECT_EQ(dl_status.error_code(), grpc::StatusCode::RESOURCE_EXHAUSTED);

    // DeleteFile (metadata domain) remains available
    v1::DeleteFileRequest del_req;
    del_req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    v1::DeleteFileResponse del_resp;

    auto del_status = service.DeleteFile(&gateway_ctx, &del_req, &del_resp);
    EXPECT_NE(del_status.error_code(), grpc::StatusCode::RESOURCE_EXHAUSTED);
}

// ============================================================================
// TC3: Storage Concurrency Bounded Ceilings
// ============================================================================
TEST(FilesConcurrencyIntegrationTest, BoundedStorageCeilingUnderConcurrentLoad) {
    constexpr size_t k_storage_limit = 4;
    auto mock_s3 = std::make_shared<MockStorageEngine>();
    mock_s3->artificial_delay = std::chrono::milliseconds(15);

    auto storage_bulkhead =
        ConcurrencyBulkhead::create("minio_storage", k_storage_limit, std::chrono::milliseconds(500));
    BoundedStorageEngine bounded_engine(mock_s3, storage_bulkhead);

    std::vector<std::thread> threads;
    for (size_t i = 0; i < 16; ++i) {
        threads.emplace_back(
            [&bounded_engine] { bounded_engine.put_chunk("tx", 0, "encrypted_bytes", "expected_hash"); });
    }

    for (auto& t : threads) {
        t.join();
    }

    EXPECT_LE(mock_s3->max_concurrent_ops.load(), k_storage_limit);
    EXPECT_EQ(storage_bulkhead->active_permits(), 0);
}

// ============================================================================
// TC4: Memory Budget Allocation & Exhaustion Rejection
// ============================================================================
TEST(FilesConcurrencyIntegrationTest, GlobalMemoryBudgetGuaranteesBoundedFootprint) {
    constexpr size_t k_total_memory_budget = 4096; // 4 KiB
    auto memory_tracker = MemoryBufferTracker::create(k_total_memory_budget);

    FilesServiceDependencies deps{.memory_tracker = memory_tracker, .max_chunk_request_bytes = 4096};
    FilesServiceImpl service(deps, "gateway");
    TestAuthContext gateway_ctx(true);

    // Allocate 3000 bytes
    auto res1 = memory_tracker->try_reserve(3000);
    ASSERT_TRUE(res1.holds_reservation());

    // Incoming chunk of 1500 bytes exceeds remaining 1096 bytes budget
    v1::UploadChunkRequest req;
    req.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_chunk_index(0);
    req.set_chunk_size_bytes(1500);
    req.set_encrypted_data(std::string(1500, 'M'));
    v1::UploadChunkResponse resp;

    auto status = service.UploadChunk(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::RESOURCE_EXHAUSTED);

    // Free res1 and retry -> succeeds past memory check
    res1.release();
    EXPECT_EQ(memory_tracker->current_reserved_bytes(), 0);
}

// ============================================================================
// TC5: Fast Rejection of Oversized Chunk Request
// ============================================================================
TEST(FilesConcurrencyIntegrationTest, RejectsOversizedChunkBeforeBufferAllocation) {
    auto memory_tracker = MemoryBufferTracker::create(1024 * 1024);
    FilesServiceDependencies deps{
        .memory_tracker = memory_tracker,
        .max_chunk_request_bytes = 5 * 1024 * 1024 // 5 MiB
    };
    FilesServiceImpl service(deps, "gateway");
    TestAuthContext gateway_ctx(true);

    v1::UploadChunkRequest req;
    req.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_chunk_index(0);
    req.set_chunk_size_bytes(6 * 1024 * 1024);     // 6 MiB > 5 MiB
    req.set_encrypted_data(std::string(100, 'O')); // Claimed size is 6 MiB
    v1::UploadChunkResponse resp;

    auto status = service.UploadChunk(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
    // Zero memory buffer was allocated
    EXPECT_EQ(memory_tracker->current_reserved_bytes(), 0);
}

// ============================================================================
// TC6: Fast Rejection of Oversized File Transfer
// ============================================================================
TEST(FilesConcurrencyIntegrationTest, RejectsOversizedFileTransferAtCreation) {
    FilesServiceDependencies deps{
        .max_file_transfer_bytes = 10ULL * 1024ULL * 1024ULL * 1024ULL // 10 GiB
    };
    FilesServiceImpl service(deps, "gateway");
    TestAuthContext gateway_ctx(true);

    v1::CreateFileUploadRequest req;
    req.set_file_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    req.set_owner_user_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001");
    req.set_owner_device_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36002");
    req.set_encrypted_size_bytes(15ULL * 1024ULL * 1024ULL * 1024ULL); // 15 GiB > 10 GiB
    v1::CreateFileUploadResponse resp;

    auto status = service.CreateFileUpload(&gateway_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_NE(status.error_message().find("exceeds maximum allowed size"), std::string::npos);
}

// ============================================================================
// TC7: Non-Blocking Backpressure Pacing (No Unbounded Queuing)
// ============================================================================
TEST(FilesConcurrencyIntegrationTest, NonBlockingBackpressurePreventsUnboundedQueues) {
    auto upload_bulkhead = ConcurrencyBulkhead::create("upload", 2, std::chrono::milliseconds(10));
    FilesServiceDependencies deps{.upload_bulkhead = upload_bulkhead};
    FilesServiceImpl service(deps, "gateway");
    TestAuthContext gateway_ctx(true);

    auto p1 = upload_bulkhead->try_acquire();
    auto p2 = upload_bulkhead->try_acquire();
    ASSERT_TRUE(p1.holds_permit());
    ASSERT_TRUE(p2.holds_permit());

    // Burst of 10 requests should fail-fast immediately rather than queuing unboundedly
    auto start_time = std::chrono::steady_clock::now();
    for (int i = 0; i < 10; ++i) {
        v1::UploadChunkRequest req;
        req.set_upload_id("0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
        req.set_chunk_index(static_cast<uint32_t>(i));
        req.set_chunk_size_bytes(10);
        req.set_encrypted_data("0123456789");
        v1::UploadChunkResponse resp;

        auto status = service.UploadChunk(&gateway_ctx, &req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::RESOURCE_EXHAUSTED);
    }
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time);

    // All 10 requests were rejected within ~200ms without queue accumulation
    EXPECT_LE(elapsed.count(), 300);
}

// ============================================================================
// TC8: External Configuration Override Verification
// ============================================================================
TEST(FilesConcurrencyIntegrationTest, ConfigurationOverridesTakeImmediateEffect) {
    class MapConfigSource : public common::configuration::ConfigurationSource {
      public:
        std::optional<std::string> get(std::string_view key) const override {
            if (key == "SECURECLOUD_FILES_METADATA_MAX_CONCURRENCY")
                return "42";
            if (key == "SECURECLOUD_FILES_UPLOAD_MAX_CONCURRENCY")
                return "7";
            if (key == "SECURECLOUD_FILES_STORAGE_MAX_CONCURRENCY")
                return "18";
            return std::nullopt;
        }
    };

    MapConfigSource source;
    common::configuration::ValidationResult errors;
    auto config = FilesResourceConfig::load(source, errors);

    EXPECT_FALSE(errors.has_errors());
    EXPECT_EQ(config.metadata_domain.max_concurrency, 42);
    EXPECT_EQ(config.upload_domain.max_concurrency, 7);
    EXPECT_EQ(config.max_storage_concurrency, 18);
}

} // namespace
} // namespace securecloud::files
