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

#include "files/db/files_connection_pool.hpp"
#include "files/service/download_manager.hpp"
#include "files/service/metadata_manager.hpp"
#include "files/service/storage_engine.hpp"
#include "files/service/upload_session_manager.hpp"
#include "files/storage/s3_client.hpp"

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
};

/// Implementation of the securecloud.files.v1.FilesService gRPC interface.
/// In FILES-001, serves as the authoritative service skeleton:
/// - Registers all 7 RPC endpoints returning deterministic UNIMPLEMENTED status.
/// - Enforces mTLS client certificate SAN peer identity verification (Gateway: DNS:gateway).
/// - Implements secret-safe operational logging (never logging ciphertext or secret keys).
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

    grpc::Status CreateFileUpload(const grpc::AuthContext* auth_ctx, const v1::CreateFileUploadRequest* request,
                                  v1::CreateFileUploadResponse* response);

    grpc::Status UploadChunk(const grpc::AuthContext* auth_ctx, const v1::UploadChunkRequest* request,
                             v1::UploadChunkResponse* response);

    grpc::Status FinalizeFileUpload(const grpc::AuthContext* auth_ctx, const v1::FinalizeFileUploadRequest* request,
                                    v1::FinalizeFileUploadResponse* response);

    grpc::Status GetFileMetadata(const grpc::AuthContext* auth_ctx, const v1::GetFileMetadataRequest* request,
                                 v1::GetFileMetadataResponse* response);

    grpc::Status DownloadChunk(const grpc::AuthContext* auth_ctx, const v1::DownloadChunkRequest* request,
                               v1::DownloadChunkResponse* response);

    grpc::Status CancelFileUpload(const grpc::AuthContext* auth_ctx, const v1::CancelFileUploadRequest* request,
                                  v1::CancelFileUploadResponse* response);

    grpc::Status DeleteFile(const grpc::AuthContext* auth_ctx, const v1::DeleteFileRequest* request,
                            v1::DeleteFileResponse* response);

    // --- Security & Identity Helpers ---

    [[nodiscard]] std::optional<std::string> extract_peer_identity(const grpc::AuthContext* auth_ctx) const;
    [[nodiscard]] bool verify_caller_identity(const grpc::AuthContext* auth_ctx,
                                              std::string_view expected_service) const;

  private:
    grpc::Status check_peer_authorization(const grpc::AuthContext* auth_ctx, std::string_view rpc_name,
                                          std::string& out_peer) const;

    FilesServiceDependencies deps_;
    std::string expected_client_identity_;
};

} // namespace securecloud::files::service
