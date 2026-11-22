#pragma once

// Pull in gRPC and Windows headers first, then undefine conflicting Win32 macros
#include <grpcpp/grpcpp.h>

#ifdef DeleteFile
#undef DeleteFile
#endif

#include "securecloud/files/v1/files.grpc.pb.h"

#ifdef DeleteFile
#undef DeleteFile
#endif

#include "files/concurrency/concurrency_bulkhead.hpp"
#include "files/concurrency/memory_buffer_tracker.hpp"
#include "files/db/files_connection_pool.hpp"
#include "files/service/chunk_storage_service.hpp"
#include "files/service/download_manager.hpp"
#include "files/service/file_capability_manager.hpp"
#include "files/service/file_finalization_service.hpp"
#include "files/service/file_lifecycle_service.hpp"
#include "files/service/files_audit_event_publisher.hpp"
#include "files/service/files_caller_context.hpp"
#include "files/service/metadata_manager.hpp"
#include "files/service/object_assembly_engine.hpp"
#include "files/service/storage_engine.hpp"
#include "files/service/upload_session_manager.hpp"
#include "files/storage/s3_client.hpp"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#ifdef DeleteFile
#undef DeleteFile
#endif

namespace securecloud::files::service {

/// Dependency bundle for FilesServiceImpl enabling modular injection.
struct FilesServiceDependencies {
    std::shared_ptr<db::FilesDbConnectionPool> db_pool{nullptr};
    std::shared_ptr<storage::S3Client> s3_client{nullptr};
    std::shared_ptr<IUploadSessionManager> upload_session_manager{nullptr};
    std::shared_ptr<IDownloadManager> download_manager{nullptr};
    std::shared_ptr<IStorageEngine> storage_engine{nullptr};
    std::shared_ptr<IMetadataManager> metadata_manager{nullptr};
    std::shared_ptr<FileLifecycleService> lifecycle_service{nullptr};
    std::shared_ptr<ChunkStorageService> chunk_storage_service{nullptr};
    std::shared_ptr<ObjectAssemblyEngine> object_assembly_engine{nullptr};
    std::shared_ptr<FileFinalizationService> finalization_service{nullptr};
    std::shared_ptr<IFileCapabilityManager> capability_manager{nullptr};

    // AUDIT-015-T03: Centralized Audit Publisher injected into the service
    std::shared_ptr<FilesAuditEventPublisher> audit_publisher{nullptr};

    // Concurrency Bulkheads & Resource Controls (FILES-009)
    std::shared_ptr<ConcurrencyBulkhead> metadata_bulkhead{nullptr};
    std::shared_ptr<ConcurrencyBulkhead> upload_bulkhead{nullptr};
    std::shared_ptr<ConcurrencyBulkhead> download_bulkhead{nullptr};
    std::shared_ptr<MemoryBufferTracker> memory_tracker{nullptr};
    size_t max_chunk_request_bytes{5 * 1024 * 1024};
    uint64_t max_file_transfer_bytes{10ULL * 1024ULL * 1024ULL * 1024ULL};
};

/// Implementation of the securecloud.files.v1.FilesService gRPC interface.
class FilesServiceImpl final : public v1::FilesService::Service {
  public:
    static constexpr std::string_view k_unimplemented_skeleton_message =
        "FilesService method not implemented in FILES-001 skeleton";

    explicit FilesServiceImpl(FilesServiceDependencies deps = {}, std::string expected_client_identity = "");

    FilesServiceImpl(std::shared_ptr<db::FilesDbConnectionPool> db_pool, std::shared_ptr<storage::S3Client> s3_client,
                     std::string expected_client_identity = "");

    ~FilesServiceImpl() override = default;

    FilesServiceImpl(const FilesServiceImpl&) = delete;
    FilesServiceImpl& operator=(const FilesServiceImpl&) = delete;
    FilesServiceImpl(FilesServiceImpl&&) = delete;
    FilesServiceImpl& operator=(FilesServiceImpl&&) = delete;

    [[nodiscard]] const std::string& expected_client_identity() const noexcept;
    void set_expected_client_identity(std::string expected_client_identity);

    [[nodiscard]] const FilesServiceDependencies& dependencies() const noexcept;

    // --- gRPC Service Virtual Overrides ---

    grpc::Status CreateFileUpload(grpc::ServerContext* context, const v1::CreateFileUploadRequest* request,
                                  v1::CreateFileUploadResponse* response) override;

    grpc::Status UploadChunk(grpc::ServerContext* context, const v1::UploadChunkRequest* request,
                             v1::UploadChunkResponse* response) override;

    grpc::Status FinalizeFileUpload(grpc::ServerContext* context, const v1::FinalizeFileUploadRequest* request,
                                    v1::FinalizeFileUploadResponse* response) override;

    grpc::Status GetFileMetadata(grpc::ServerContext* context, const v1::GetFileMetadataRequest* request,
                                 v1::GetFileMetadataResponse* response) override;

    grpc::Status DownloadChunk(grpc::ServerContext* context, const v1::DownloadChunkRequest* request,
                               v1::DownloadChunkResponse* response) override;

    grpc::Status CancelFileUpload(grpc::ServerContext* context, const v1::CancelFileUploadRequest* request,
                                  v1::CancelFileUploadResponse* response) override;

    grpc::Status DeleteFile(grpc::ServerContext* context, const v1::DeleteFileRequest* request,
                            v1::DeleteFileResponse* response) override;

    // --- Direct AuthContext Overloads (for unit testing and direct invocation) ---
    // AUDIT-015-T03: All inner RPC methods now expect client_metadata for robust Correlation Context Extraction

    grpc::Status CreateFileUpload(const grpc::AuthContext* auth_ctx, const v1::CreateFileUploadRequest* request,
                                  v1::CreateFileUploadResponse* response,
                                  const std::multimap<grpc::string_ref, grpc::string_ref>& client_metadata);

    grpc::Status UploadChunk(const grpc::AuthContext* auth_ctx, const v1::UploadChunkRequest* request,
                             v1::UploadChunkResponse* response,
                             const std::multimap<grpc::string_ref, grpc::string_ref>& client_metadata);

    grpc::Status FinalizeFileUpload(const grpc::AuthContext* auth_ctx, const v1::FinalizeFileUploadRequest* request,
                                    v1::FinalizeFileUploadResponse* response,
                                    const std::multimap<grpc::string_ref, grpc::string_ref>& client_metadata);

    grpc::Status GetFileMetadata(const grpc::AuthContext* auth_ctx, const v1::GetFileMetadataRequest* request,
                                 v1::GetFileMetadataResponse* response,
                                 const std::multimap<grpc::string_ref, grpc::string_ref>& client_metadata);

    grpc::Status DownloadChunk(const grpc::AuthContext* auth_ctx, const v1::DownloadChunkRequest* request,
                               v1::DownloadChunkResponse* response,
                               const std::multimap<grpc::string_ref, grpc::string_ref>& client_metadata);

    grpc::Status CancelFileUpload(const grpc::AuthContext* auth_ctx, const v1::CancelFileUploadRequest* request,
                                  v1::CancelFileUploadResponse* response,
                                  const std::multimap<grpc::string_ref, grpc::string_ref>& client_metadata);

    grpc::Status DeleteFile(const grpc::AuthContext* auth_ctx, const v1::DeleteFileRequest* request,
                            v1::DeleteFileResponse* response,
                            const std::multimap<grpc::string_ref, grpc::string_ref>& client_metadata);

    // --- Security & Identity Helpers ---

    [[nodiscard]] std::optional<std::string> extract_peer_identity(const grpc::AuthContext* auth_ctx) const;
    [[nodiscard]] bool verify_caller_identity(const grpc::AuthContext* auth_ctx,
                                              std::string_view expected_service) const;

  private:
    grpc::Status check_peer_authorization(const grpc::AuthContext* auth_ctx, std::string_view rpc_name,
                                          std::string& out_peer) const;

    // AUDIT-015-T03: Correlation and Call Context extraction
    [[nodiscard]] FilesCallerContext
    extract_caller_context(const std::multimap<grpc::string_ref, grpc::string_ref>& client_metadata,
                           const std::string& peer_identity, const std::string& fallback_user_id = "") const;

    FilesServiceDependencies deps_;
    std::string expected_client_identity_;
};

} // namespace securecloud::files::service
