#include "files/service/files_service_impl.hpp"

#include "files/domain/metadata_validator.hpp"
#include "files/repository/file_transfer_repository.hpp"
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
        : rpc_name_(rpc_name), peer_identity_(std::move(peer_identity)), start_time_(std::chrono::steady_clock::now()) {
        std::cout << "[SecureCloud] [files] RPC " << rpc_name_ << " started (peer: '" << peer_identity_ << "')\n";
    }

    void finish(const grpc::Status& status) {
        auto elapsed_us =
            std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start_time_)
                .count();
        std::cout << "[SecureCloud] [files] RPC " << rpc_name_ << " completed with code " << status.error_code()
                  << " in " << elapsed_us << " us (peer: '" << peer_identity_ << "')\n";
    }

  private:
    std::string_view rpc_name_;
    std::string peer_identity_;
    std::chrono::steady_clock::time_point start_time_;
};

} // namespace

FilesServiceImpl::FilesServiceImpl(FilesServiceDependencies deps, std::string expected_client_identity)
    : deps_(std::move(deps)), expected_client_identity_(std::move(expected_client_identity)) {
    if (!deps_.lifecycle_service && deps_.db_pool) {
        deps_.lifecycle_service = std::make_shared<FileLifecycleService>(deps_.db_pool);
    }
}

FilesServiceImpl::FilesServiceImpl(std::shared_ptr<db::FilesDbConnectionPool> db_pool,
                                   std::shared_ptr<storage::S3Client> s3_client, std::string expected_client_identity)
    : deps_{
          .db_pool = db_pool,
          .s3_client = std::move(s3_client),
          .upload_session_manager = std::make_shared<UploadSessionManager>(),
          .download_manager = std::make_shared<DownloadManager>(),
          .storage_engine = std::make_shared<StorageEngine>(),
          .metadata_manager = std::make_shared<MetadataManager>(db_pool),
          .lifecycle_service = std::make_shared<FileLifecycleService>(db_pool),
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

grpc::Status FilesServiceImpl::check_peer_authorization(const grpc::AuthContext* auth_ctx, std::string_view rpc_name,
                                                        std::string& out_peer) const {
    if (!expected_client_identity_.empty()) {
        if (auth_ctx == nullptr || !auth_ctx->IsPeerAuthenticated()) {
            std::cerr << "[SecureCloud] [files] RPC " << rpc_name
                      << " rejected: peer unauthenticated (status: UNAUTHENTICATED)\n";
            return {grpc::StatusCode::UNAUTHENTICATED, "Mutual TLS peer authentication required"};
        }

        auto peer_opt = extract_peer_identity(auth_ctx);
        if (!peer_opt.has_value() || peer_opt.value() != expected_client_identity_) {
            std::cerr << "[SecureCloud] [files] RPC " << rpc_name << " rejected: peer identity '"
                      << (peer_opt ? *peer_opt : "none") << "' mismatch (expected '" << expected_client_identity_
                      << "') (status: PERMISSION_DENIED)\n";
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

grpc::Status FilesServiceImpl::CreateFileUpload(grpc::ServerContext* context,
                                                const v1::CreateFileUploadRequest* request,
                                                v1::CreateFileUploadResponse* response) {
    const grpc::AuthContext* auth_ctx = (context != nullptr) ? context->auth_context().get() : nullptr;
    return CreateFileUpload(auth_ctx, request, response);
}

grpc::Status FilesServiceImpl::CreateFileUpload(const grpc::AuthContext* auth_ctx,
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

    std::cout << "[SecureCloud] [files] RPC CreateFileUpload request received for file_id='" << request->file_id()
              << "' owner_user_id='" << request->owner_user_id()
              << "' (expected_chunks=" << request->expected_chunk_count() << ")\n";

    if (!deps_.lifecycle_service) {
        auto status = grpc::Status(grpc::StatusCode::INTERNAL, "FileLifecycleService is not initialized");
        logger.finish(status);
        return status;
    }

    std::string target_file_id = request->file_id().empty() ? generate_uuid_v7() : request->file_id();

    CreateFileRequestDto dto{
        .file_id = target_file_id,
        .owner_user_id = request->owner_user_id(),
        .owner_device_id = request->owner_device_id(),
        .conversation_id =
            request->conversation_id().empty() ? std::nullopt : std::make_optional(request->conversation_id()),
        .encrypted_size_bytes = request->encrypted_size_bytes(),
        .expected_chunk_count = request->expected_chunk_count(),
        .encryption_algorithm = request->encryption_version().empty() ? std::string(k_approved_encryption_algorithm)
                                                                      : request->encryption_version(),
    };

    if (!request->client_crypto_metadata().empty()) {
        auto unpack_res = unpack_client_crypto_metadata(request->client_crypto_metadata(), dto);
        if (!unpack_res) {
            auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                                       "Invalid client_crypto_metadata: " + unpack_res.error_message);
            logger.finish(status);
            return status;
        }
    } else {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "client_crypto_metadata is required");
        logger.finish(status);
        return status;
    }

    auto now = std::chrono::system_clock::now();
    try {
        deps_.lifecycle_service->create_file(dto, now);
    } catch (const FileLifecycleValidationException& ex) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, ex.what());
        logger.finish(status);
        return status;
    } catch (const std::exception& ex) {
        auto status = grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
        logger.finish(status);
        return status;
    }

    std::string upload_id = generate_uuid_v7();
    auto expiry_tp = now + std::chrono::hours(24);
    int64_t expires_ms = std::chrono::duration_cast<std::chrono::milliseconds>(expiry_tp.time_since_epoch()).count();

    // If db pool is present, persist transfer session record
    if (deps_.db_pool) {
        try {
            pqxx::work tx;
            FileTransferRepository transfer_repo(deps_.db_pool);
            FileTransferEntity transfer{
                .transfer_id = upload_id,
                .file_id = target_file_id,
                .transfer_type = TransferType::Upload,
                .initiator_user_id = request->owner_user_id(),
                .initiator_device_id = request->owner_device_id(),
                .status = TransferStatus::Created,
                .total_chunks = static_cast<int32_t>(dto.expected_chunk_count),
                .accepted_chunks = 0,
                .created_at = now,
                .updated_at = now,
                .expires_at = expiry_tp,
            };
            transfer_repo.create_transfer(transfer, tx);
            tx.commit();
        } catch (const std::exception& ex) {
            std::cerr << "[SecureCloud] [files] Warning: Failed to persist transfer record: " << ex.what() << "\n";
        }
    }

    response->set_upload_id(upload_id);
    response->set_file_id(target_file_id);
    response->set_status(v1::TRANSFER_STATUS_PENDING);
    response->set_expires_at_unix_ms(expires_ms);

    auto status = grpc::Status::OK;
    logger.finish(status);
    return status;
}

// ==========================================
// 2. Upload Chunk
// ==========================================

grpc::Status FilesServiceImpl::UploadChunk(grpc::ServerContext* context, const v1::UploadChunkRequest* request,
                                           v1::UploadChunkResponse* response) {
    const grpc::AuthContext* auth_ctx = (context != nullptr) ? context->auth_context().get() : nullptr;
    return UploadChunk(auth_ctx, request, response);
}

grpc::Status FilesServiceImpl::UploadChunk(const grpc::AuthContext* auth_ctx, const v1::UploadChunkRequest* request,
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
    std::cout << "[SecureCloud] [files] RPC UploadChunk request received for upload_id='" << request->upload_id()
              << "' chunk_index=" << request->chunk_index() << " size=" << request->chunk_size_bytes() << " bytes\n";

    auto status = grpc::Status(grpc::StatusCode::UNIMPLEMENTED, std::string(k_unimplemented_skeleton_message));
    logger.finish(status);
    return status;
}

// ==========================================
// 3. Finalize File Upload
// ==========================================

grpc::Status FilesServiceImpl::FinalizeFileUpload(grpc::ServerContext* context,
                                                  const v1::FinalizeFileUploadRequest* request,
                                                  v1::FinalizeFileUploadResponse* response) {
    const grpc::AuthContext* auth_ctx = (context != nullptr) ? context->auth_context().get() : nullptr;
    return FinalizeFileUpload(auth_ctx, request, response);
}

grpc::Status FilesServiceImpl::FinalizeFileUpload(const grpc::AuthContext* auth_ctx,
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

    if (!request->file_id().empty() && !is_valid_uuid(request->file_id())) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid file_id format");
        logger.finish(status);
        return status;
    }

    // Lifecycle validation hook (FILES-004-T04): verify that UPLOADING -> FINALIZING is legal
    if (!is_valid_state_transition(FileStatus::Uploading, FileStatus::Finalizing)) {
        auto status = grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
                                   "State transition from UPLOADING to FINALIZING is disallowed");
        logger.finish(status);
        return status;
    }

    std::cout << "[SecureCloud] [files] RPC FinalizeFileUpload request received for upload_id='" << request->upload_id()
              << "' file_id='" << request->file_id() << "'\n";

    auto status = grpc::Status(grpc::StatusCode::UNIMPLEMENTED, std::string(k_unimplemented_skeleton_message));
    logger.finish(status);
    return status;
}

// ==========================================
// 4. Get File Metadata
// ==========================================

grpc::Status FilesServiceImpl::GetFileMetadata(grpc::ServerContext* context, const v1::GetFileMetadataRequest* request,
                                               v1::GetFileMetadataResponse* response) {
    const grpc::AuthContext* auth_ctx = (context != nullptr) ? context->auth_context().get() : nullptr;
    return GetFileMetadata(auth_ctx, request, response);
}

grpc::Status FilesServiceImpl::GetFileMetadata(const grpc::AuthContext* auth_ctx,
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

    std::cout << "[SecureCloud] [files] RPC GetFileMetadata request received for file_id='" << request->file_id()
              << "'\n";

    if (!is_valid_uuid(request->file_id())) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid file_id format");
        logger.finish(status);
        return status;
    }

    if (!deps_.lifecycle_service) {
        auto status = grpc::Status(grpc::StatusCode::INTERNAL, "FileLifecycleService is not initialized");
        logger.finish(status);
        return status;
    }

    std::optional<FileMetadataSummary> summary_opt;
    try {
        summary_opt = deps_.lifecycle_service->get_file_metadata(request->file_id(), peer_identity);
    } catch (const UnauthorizedFileAccessException& ex) {
        auto status = grpc::Status(grpc::StatusCode::PERMISSION_DENIED, ex.what());
        logger.finish(status);
        return status;
    } catch (const std::exception& ex) {
        auto status = grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
        logger.finish(status);
        return status;
    }

    if (!summary_opt.has_value()) {
        auto status = grpc::Status(grpc::StatusCode::NOT_FOUND, "File not found: " + request->file_id());
        logger.finish(status);
        return status;
    }

    const auto& summary = *summary_opt;
    response->set_file_id(summary.file.file_id);
    response->set_lifecycle_state(to_proto(summary.file.status));
    response->set_encrypted_size_bytes(static_cast<uint64_t>(summary.file.encrypted_size));
    response->set_chunk_count(summary.expected_chunk_count);
    response->set_encryption_version(summary.file.encryption_algorithm);

    if (summary.active_version.has_value()) {
        response->set_ciphertext_integrity_hash(summary.active_version->checksum_sha256);
        auto avail_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(summary.active_version->created_at.time_since_epoch())
                .count();
        response->set_available_at_unix_ms(avail_ms);
    } else {
        response->set_ciphertext_integrity_hash("");
        response->set_available_at_unix_ms(0);
    }

    auto created_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(summary.file.created_at.time_since_epoch()).count();
    response->set_created_at_unix_ms(created_ms);

    int64_t expires_ms = 0;
    if (summary.file.retention_until.has_value()) {
        expires_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(summary.file.retention_until->time_since_epoch())
                .count();
    }
    response->set_expires_at_unix_ms(expires_ms);

    auto status = grpc::Status::OK;
    logger.finish(status);
    return status;
}

// ==========================================
// 5. Download Chunk
// ==========================================

grpc::Status FilesServiceImpl::DownloadChunk(grpc::ServerContext* context, const v1::DownloadChunkRequest* request,
                                             v1::DownloadChunkResponse* response) {
    const grpc::AuthContext* auth_ctx = (context != nullptr) ? context->auth_context().get() : nullptr;
    return DownloadChunk(auth_ctx, request, response);
}

grpc::Status FilesServiceImpl::DownloadChunk(const grpc::AuthContext* auth_ctx, const v1::DownloadChunkRequest* request,
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

    std::cout << "[SecureCloud] [files] RPC DownloadChunk request received for file_id='" << request->file_id()
              << "' chunk_index=" << request->chunk_index() << "\n";

    auto status = grpc::Status(grpc::StatusCode::UNIMPLEMENTED, std::string(k_unimplemented_skeleton_message));
    logger.finish(status);
    return status;
}

// ==========================================
// 6. Cancel File Upload
// ==========================================

grpc::Status FilesServiceImpl::CancelFileUpload(grpc::ServerContext* context,
                                                const v1::CancelFileUploadRequest* request,
                                                v1::CancelFileUploadResponse* response) {
    const grpc::AuthContext* auth_ctx = (context != nullptr) ? context->auth_context().get() : nullptr;
    return CancelFileUpload(auth_ctx, request, response);
}

grpc::Status FilesServiceImpl::CancelFileUpload(const grpc::AuthContext* auth_ctx,
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

    std::cout << "[SecureCloud] [files] RPC CancelFileUpload request received for upload_id='" << request->upload_id()
              << "'\n";

    auto status = grpc::Status(grpc::StatusCode::UNIMPLEMENTED, std::string(k_unimplemented_skeleton_message));
    logger.finish(status);
    return status;
}

// ==========================================
// 7. Delete File
// ==========================================

grpc::Status FilesServiceImpl::DeleteFile(grpc::ServerContext* context, const v1::DeleteFileRequest* request,
                                          v1::DeleteFileResponse* response) {
    const grpc::AuthContext* auth_ctx = (context != nullptr) ? context->auth_context().get() : nullptr;
    return DeleteFile(auth_ctx, request, response);
}

grpc::Status FilesServiceImpl::DeleteFile(const grpc::AuthContext* auth_ctx, const v1::DeleteFileRequest* request,
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

    std::cout << "[SecureCloud] [files] RPC DeleteFile request received for file_id='" << request->file_id() << "'\n";

    if (!is_valid_uuid(request->file_id())) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid file_id format");
        logger.finish(status);
        return status;
    }

    if (!deps_.lifecycle_service) {
        auto status = grpc::Status(grpc::StatusCode::INTERNAL, "FileLifecycleService is not initialized");
        logger.finish(status);
        return status;
    }

    try {
        deps_.lifecycle_service->delete_file(request->file_id(), peer_identity, "Client requested deletion");
    } catch (const FileNotFoundException& ex) {
        auto status = grpc::Status(grpc::StatusCode::NOT_FOUND, ex.what());
        logger.finish(status);
        return status;
    } catch (const UnauthorizedFileAccessException& ex) {
        auto status = grpc::Status(grpc::StatusCode::PERMISSION_DENIED, ex.what());
        logger.finish(status);
        return status;
    } catch (const InvalidLifecycleTransitionException& ex) {
        auto status = grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, ex.what());
        logger.finish(status);
        return status;
    } catch (const std::exception& ex) {
        auto status = grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
        logger.finish(status);
        return status;
    }

    response->set_file_id(request->file_id());
    response->set_lifecycle_state(v1::FILE_LIFECYCLE_STATE_DELETED);
    response->set_deleted(true);

    auto status = grpc::Status::OK;
    logger.finish(status);
    return status;
}

} // namespace securecloud::files::service
