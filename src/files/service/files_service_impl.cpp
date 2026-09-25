#include "files/service/files_service_impl.hpp"

#include "securecloud/security/mtls_config.hpp"

#include <chrono>
#include <iostream>
#include <utility>

#ifdef DeleteFile
#undef DeleteFile
#endif

namespace securecloud::files::service {

namespace {

/// RAII helper for structured, secret-safe operational logging and timing.
/// Strictly logs method metadata, duration, peer identity, and status code.
/// Never logs payload ciphertext bytes, cryptographic keys, or S3 credentials.
class RpcScopeLogger {
public:
    RpcScopeLogger(std::string_view rpc_name, std::string peer_identity)
        : rpc_name_(rpc_name), peer_identity_(std::move(peer_identity)),
          start_time_(std::chrono::steady_clock::now()) {
        std::cout << "[SecureCloud] [files] RPC " << rpc_name_
                  << " started (peer: '" << peer_identity_ << "')\n";
    }

    void finish(const grpc::Status& status) {
        auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start_time_).count();
        std::cout << "[SecureCloud] [files] RPC " << rpc_name_
                  << " completed with code " << status.error_code()
                  << " in " << elapsed_us << " us (peer: '" << peer_identity_ << "')\n";
    }

private:
    std::string_view rpc_name_;
    std::string peer_identity_;
    std::chrono::steady_clock::time_point start_time_;
};

} // namespace

FilesServiceImpl::FilesServiceImpl(FilesServiceDependencies deps, std::string expected_client_identity)
    : deps_(std::move(deps)), expected_client_identity_(std::move(expected_client_identity)) {}

FilesServiceImpl::FilesServiceImpl(std::shared_ptr<db::FilesDbConnectionPool> db_pool,
                                   std::shared_ptr<storage::S3Client> s3_client,
                                   std::string expected_client_identity)
    : deps_{
          .db_pool = std::move(db_pool),
          .s3_client = std::move(s3_client),
          .upload_session_manager = std::make_shared<UploadSessionManager>(),
          .download_manager = std::make_shared<DownloadManager>(),
          .storage_engine = std::make_shared<StorageEngine>(),
          .metadata_manager = std::make_shared<MetadataManager>(),
      },
      expected_client_identity_(std::move(expected_client_identity)) {}

const std::string& FilesServiceImpl::expected_client_identity() const noexcept {
    return expected_client_identity_;
}

void FilesServiceImpl::set_expected_client_identity(std::string expected_client_identity) {
    expected_client_identity_ = std::move(expected_client_identity);
}

const FilesServiceDependencies& FilesServiceImpl::dependencies() const noexcept {
    return deps_;
}

std::optional<std::string> FilesServiceImpl::extract_peer_identity(const grpc::AuthContext* auth_ctx) const {
    if (auth_ctx == nullptr) {
        return std::nullopt;
    }
    return common::security::extract_peer_service_identity(*auth_ctx);
}

bool FilesServiceImpl::verify_caller_identity(const grpc::AuthContext* auth_ctx,
                                              std::string_view expected_service) const {
    if (auth_ctx == nullptr) {
        return false;
    }
    return common::security::verify_peer_service_identity(*auth_ctx, expected_service);
}

grpc::Status FilesServiceImpl::check_peer_authorization(const grpc::AuthContext* auth_ctx,
                                                        std::string_view rpc_name,
                                                        std::string& out_peer) const {
    if (!expected_client_identity_.empty()) {
        if (auth_ctx == nullptr || !auth_ctx->IsPeerAuthenticated()) {
            std::cerr << "[SecureCloud] [files] RPC " << rpc_name
                      << " rejected: peer unauthenticated (status: UNAUTHENTICATED)\n";
            return {grpc::StatusCode::UNAUTHENTICATED, "Mutual TLS peer authentication required"};
        }

        auto peer_opt = extract_peer_identity(auth_ctx);
        if (!peer_opt.has_value() || peer_opt.value() != expected_client_identity_) {
            std::cerr << "[SecureCloud] [files] RPC " << rpc_name
                      << " rejected: peer identity '" << (peer_opt ? *peer_opt : "none")
                      << "' mismatch (expected '" << expected_client_identity_ << "') (status: PERMISSION_DENIED)\n";
            return {grpc::StatusCode::PERMISSION_DENIED, "Caller peer identity not authorized"};
        }
        out_peer = *peer_opt;
    } else if (auth_ctx != nullptr && auth_ctx->IsPeerAuthenticated()) {
        auto peer_opt = extract_peer_identity(auth_ctx);
        out_peer = peer_opt.value_or("authenticated_peer");
    } else {
        out_peer = "unauthenticated";
    }
    return grpc::Status::OK;
}

// ==========================================
// 1. Create File Upload
// ==========================================

grpc::Status FilesServiceImpl::CreateFileUpload(
    grpc::ServerContext* context,
    const v1::CreateFileUploadRequest* request,
    v1::CreateFileUploadResponse* response) {
    const grpc::AuthContext* auth_ctx = (context != nullptr) ? context->auth_context().get() : nullptr;
    return CreateFileUpload(auth_ctx, request, response);
}

grpc::Status FilesServiceImpl::CreateFileUpload(
    const grpc::AuthContext* auth_ctx,
    const v1::CreateFileUploadRequest* request,
    v1::CreateFileUploadResponse* response) {
    std::string peer_identity;
    auto auth_status = check_peer_authorization(auth_ctx, "CreateFileUpload", peer_identity);
    if (!auth_status.ok()) {
        return auth_status;
    }

    RpcScopeLogger logger("CreateFileUpload", peer_identity);

    if (!request || !response) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid request or response pointer");
        logger.finish(status);
        return status;
    }

    std::cout << "[SecureCloud] [files] RPC CreateFileUpload request received for file_id='"
              << request->file_id() << "' owner_user_id='" << request->owner_user_id()
              << "' (expected_chunks=" << request->expected_chunk_count() << ")\n";

    auto status = grpc::Status(grpc::StatusCode::UNIMPLEMENTED, std::string(k_unimplemented_skeleton_message));
    logger.finish(status);
    return status;
}

// ==========================================
// 2. Upload Chunk
// ==========================================

grpc::Status FilesServiceImpl::UploadChunk(
    grpc::ServerContext* context,
    const v1::UploadChunkRequest* request,
    v1::UploadChunkResponse* response) {
    const grpc::AuthContext* auth_ctx = (context != nullptr) ? context->auth_context().get() : nullptr;
    return UploadChunk(auth_ctx, request, response);
}

grpc::Status FilesServiceImpl::UploadChunk(
    const grpc::AuthContext* auth_ctx,
    const v1::UploadChunkRequest* request,
    v1::UploadChunkResponse* response) {
    std::string peer_identity;
    auto auth_status = check_peer_authorization(auth_ctx, "UploadChunk", peer_identity);
    if (!auth_status.ok()) {
        return auth_status;
    }

    RpcScopeLogger logger("UploadChunk", peer_identity);

    if (!request || !response) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid request or response pointer");
        logger.finish(status);
        return status;
    }

    // Zero-Plaintext Invariant: log upload_id, chunk_index, and size only; never log encrypted_data bytes
    std::cout << "[SecureCloud] [files] RPC UploadChunk request received for upload_id='"
              << request->upload_id() << "' chunk_index=" << request->chunk_index()
              << " size=" << request->chunk_size_bytes() << " bytes\n";

    auto status = grpc::Status(grpc::StatusCode::UNIMPLEMENTED, std::string(k_unimplemented_skeleton_message));
    logger.finish(status);
    return status;
}

// ==========================================
// 3. Finalize File Upload
// ==========================================

grpc::Status FilesServiceImpl::FinalizeFileUpload(
    grpc::ServerContext* context,
    const v1::FinalizeFileUploadRequest* request,
    v1::FinalizeFileUploadResponse* response) {
    const grpc::AuthContext* auth_ctx = (context != nullptr) ? context->auth_context().get() : nullptr;
    return FinalizeFileUpload(auth_ctx, request, response);
}

grpc::Status FilesServiceImpl::FinalizeFileUpload(
    const grpc::AuthContext* auth_ctx,
    const v1::FinalizeFileUploadRequest* request,
    v1::FinalizeFileUploadResponse* response) {
    std::string peer_identity;
    auto auth_status = check_peer_authorization(auth_ctx, "FinalizeFileUpload", peer_identity);
    if (!auth_status.ok()) {
        return auth_status;
    }

    RpcScopeLogger logger("FinalizeFileUpload", peer_identity);

    if (!request || !response) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid request or response pointer");
        logger.finish(status);
        return status;
    }

    std::cout << "[SecureCloud] [files] RPC FinalizeFileUpload request received for upload_id='"
              << request->upload_id() << "' file_id='" << request->file_id() << "'\n";

    auto status = grpc::Status(grpc::StatusCode::UNIMPLEMENTED, std::string(k_unimplemented_skeleton_message));
    logger.finish(status);
    return status;
}

// ==========================================
// 4. Get File Metadata
// ==========================================

grpc::Status FilesServiceImpl::GetFileMetadata(
    grpc::ServerContext* context,
    const v1::GetFileMetadataRequest* request,
    v1::GetFileMetadataResponse* response) {
    const grpc::AuthContext* auth_ctx = (context != nullptr) ? context->auth_context().get() : nullptr;
    return GetFileMetadata(auth_ctx, request, response);
}

grpc::Status FilesServiceImpl::GetFileMetadata(
    const grpc::AuthContext* auth_ctx,
    const v1::GetFileMetadataRequest* request,
    v1::GetFileMetadataResponse* response) {
    std::string peer_identity;
    auto auth_status = check_peer_authorization(auth_ctx, "GetFileMetadata", peer_identity);
    if (!auth_status.ok()) {
        return auth_status;
    }

    RpcScopeLogger logger("GetFileMetadata", peer_identity);

    if (!request || !response) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid request or response pointer");
        logger.finish(status);
        return status;
    }

    std::cout << "[SecureCloud] [files] RPC GetFileMetadata request received for file_id='"
              << request->file_id() << "'\n";

    auto status = grpc::Status(grpc::StatusCode::UNIMPLEMENTED, std::string(k_unimplemented_skeleton_message));
    logger.finish(status);
    return status;
}

// ==========================================
// 5. Download Chunk
// ==========================================

grpc::Status FilesServiceImpl::DownloadChunk(
    grpc::ServerContext* context,
    const v1::DownloadChunkRequest* request,
    v1::DownloadChunkResponse* response) {
    const grpc::AuthContext* auth_ctx = (context != nullptr) ? context->auth_context().get() : nullptr;
    return DownloadChunk(auth_ctx, request, response);
}

grpc::Status FilesServiceImpl::DownloadChunk(
    const grpc::AuthContext* auth_ctx,
    const v1::DownloadChunkRequest* request,
    v1::DownloadChunkResponse* response) {
    std::string peer_identity;
    auto auth_status = check_peer_authorization(auth_ctx, "DownloadChunk", peer_identity);
    if (!auth_status.ok()) {
        return auth_status;
    }

    RpcScopeLogger logger("DownloadChunk", peer_identity);

    if (!request || !response) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid request or response pointer");
        logger.finish(status);
        return status;
    }

    std::cout << "[SecureCloud] [files] RPC DownloadChunk request received for file_id='"
              << request->file_id() << "' chunk_index=" << request->chunk_index() << "\n";

    auto status = grpc::Status(grpc::StatusCode::UNIMPLEMENTED, std::string(k_unimplemented_skeleton_message));
    logger.finish(status);
    return status;
}

// ==========================================
// 6. Cancel File Upload
// ==========================================

grpc::Status FilesServiceImpl::CancelFileUpload(
    grpc::ServerContext* context,
    const v1::CancelFileUploadRequest* request,
    v1::CancelFileUploadResponse* response) {
    const grpc::AuthContext* auth_ctx = (context != nullptr) ? context->auth_context().get() : nullptr;
    return CancelFileUpload(auth_ctx, request, response);
}

grpc::Status FilesServiceImpl::CancelFileUpload(
    const grpc::AuthContext* auth_ctx,
    const v1::CancelFileUploadRequest* request,
    v1::CancelFileUploadResponse* response) {
    std::string peer_identity;
    auto auth_status = check_peer_authorization(auth_ctx, "CancelFileUpload", peer_identity);
    if (!auth_status.ok()) {
        return auth_status;
    }

    RpcScopeLogger logger("CancelFileUpload", peer_identity);

    if (!request || !response) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid request or response pointer");
        logger.finish(status);
        return status;
    }

    std::cout << "[SecureCloud] [files] RPC CancelFileUpload request received for upload_id='"
              << request->upload_id() << "'\n";

    auto status = grpc::Status(grpc::StatusCode::UNIMPLEMENTED, std::string(k_unimplemented_skeleton_message));
    logger.finish(status);
    return status;
}

// ==========================================
// 7. Delete File
// ==========================================

grpc::Status FilesServiceImpl::DeleteFile(
    grpc::ServerContext* context,
    const v1::DeleteFileRequest* request,
    v1::DeleteFileResponse* response) {
    const grpc::AuthContext* auth_ctx = (context != nullptr) ? context->auth_context().get() : nullptr;
    return DeleteFile(auth_ctx, request, response);
}

grpc::Status FilesServiceImpl::DeleteFile(
    const grpc::AuthContext* auth_ctx,
    const v1::DeleteFileRequest* request,
    v1::DeleteFileResponse* response) {
    std::string peer_identity;
    auto auth_status = check_peer_authorization(auth_ctx, "DeleteFile", peer_identity);
    if (!auth_status.ok()) {
        return auth_status;
    }

    RpcScopeLogger logger("DeleteFile", peer_identity);

    if (!request || !response) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid request or response pointer");
        logger.finish(status);
        return status;
    }

    std::cout << "[SecureCloud] [files] RPC DeleteFile request received for file_id='"
              << request->file_id() << "'\n";

    auto status = grpc::Status(grpc::StatusCode::UNIMPLEMENTED, std::string(k_unimplemented_skeleton_message));
    logger.finish(status);
    return status;
}

} // namespace securecloud::files::service
