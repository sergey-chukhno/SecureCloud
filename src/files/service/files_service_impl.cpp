#include "files/service/files_service_impl.hpp"

#include "files/domain/chunk_validator.hpp"
#include "files/domain/file_capability_entity.hpp"
#include "files/domain/metadata_validator.hpp"
#include "files/repository/file_transfer_repository.hpp"
#include "files/repository/files_outbox_repository.hpp"
#include "files/service/chunk_storage_service.hpp"
#include "files/service/upload_session_manager.hpp"
#include "files/storage/s3_exceptions.hpp"
#include "securecloud/files/v1/files.pb.h"
#include "securecloud/security/mtls_config.hpp"

#include <chrono>
#include <iostream>
#include <typeinfo>
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
        std::cout << "[SecureCloud] [files] RPC " << rpc_name_ << " started (peer/user: '" << peer_identity_ << "')\n";
    }

    void finish(const grpc::Status& status) {
        auto elapsed_us =
            std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start_time_)
                .count();
        std::cout << "[SecureCloud] [files] RPC " << rpc_name_ << " completed with code " << status.error_code()
                  << " in " << elapsed_us << " us (peer/user: '" << peer_identity_ << "')\n";
    }

  private:
    std::string_view rpc_name_;
    std::string peer_identity_;
    std::chrono::steady_clock::time_point start_time_;
};

[[nodiscard]] std::pair<std::string, std::string>
resolve_upload_audit_target(const std::shared_ptr<IUploadSessionManager>& session_mgr, const std::string& upload_id,
                            std::string_view cached_file_id) noexcept {
    if (!cached_file_id.empty()) {
        return {"FILE", std::string(cached_file_id)};
    }
    if (session_mgr && !upload_id.empty()) {
        try {
            if (auto session = session_mgr->get_session(upload_id); session && !session->file_id.empty()) {
                return {"FILE", session->file_id};
            }
        } catch (...) {
        }
    }
    return {"SERVICE", "files"};
}

[[nodiscard]] FilesServiceDependencies build_default_dependencies(std::shared_ptr<db::FilesDbConnectionPool> db_pool,
                                                                  std::shared_ptr<storage::S3Client> s3_client) {
    auto outbox_repo = db_pool ? std::make_shared<FilesOutboxRepository>(db_pool) : nullptr;
    auto publisher = outbox_repo ? std::make_shared<FilesAuditEventPublisher>(outbox_repo) : nullptr;
    auto assembly = s3_client ? std::make_shared<ObjectAssemblyEngine>(s3_client) : nullptr;

    FilesServiceDependencies deps;
    deps.db_pool = db_pool;
    deps.s3_client = s3_client;
    deps.audit_publisher = publisher;
    deps.storage_engine = std::make_shared<StorageEngine>();
    deps.metadata_manager = std::make_shared<MetadataManager>(db_pool);
    deps.upload_session_manager = std::make_shared<UploadSessionManager>(db_pool, nullptr, nullptr, publisher);
    deps.download_manager =
        (db_pool && s3_client)
            ? std::make_shared<DownloadManager>(db_pool, std::make_shared<ChunkDownloadEngine>(s3_client), nullptr,
                                                nullptr, nullptr, publisher)
            : std::make_shared<DownloadManager>(nullptr, nullptr, nullptr, nullptr, nullptr, publisher);
    deps.lifecycle_service =
        std::make_shared<FileLifecycleService>(db_pool, nullptr, nullptr, nullptr, outbox_repo, publisher);
    deps.chunk_storage_service =
        std::make_shared<ChunkStorageService>(db_pool, s3_client, nullptr, nullptr, nullptr, publisher);
    deps.object_assembly_engine = assembly;
    deps.finalization_service =
        (db_pool && assembly) ? std::make_shared<FileFinalizationService>(db_pool, assembly, nullptr, nullptr, nullptr,
                                                                          nullptr, outbox_repo, publisher)
                              : nullptr;
    return deps;
}

} // namespace

FilesServiceImpl::FilesServiceImpl(FilesServiceDependencies deps, std::string expected_client_identity)
    : deps_(std::move(deps)), expected_client_identity_(std::move(expected_client_identity)) {
    std::shared_ptr<FilesOutboxRepository> outbox_repo;
    if (deps_.audit_publisher && deps_.audit_publisher->outbox_repository()) {
        outbox_repo = deps_.audit_publisher->outbox_repository();
    } else if (deps_.db_pool) {
        outbox_repo = std::make_shared<FilesOutboxRepository>(deps_.db_pool);
    }

    if (!deps_.audit_publisher && outbox_repo) {
        deps_.audit_publisher = std::make_shared<FilesAuditEventPublisher>(outbox_repo);
    }

    if (!deps_.lifecycle_service && deps_.db_pool) {
        deps_.lifecycle_service = std::make_shared<FileLifecycleService>(deps_.db_pool, nullptr, nullptr, nullptr,
                                                                         outbox_repo, deps_.audit_publisher);
    }
    if (!deps_.upload_session_manager) {
        deps_.upload_session_manager =
            std::make_shared<UploadSessionManager>(deps_.db_pool, nullptr, nullptr, deps_.audit_publisher);
    }
    if (!deps_.chunk_storage_service) {
        deps_.chunk_storage_service = std::make_shared<ChunkStorageService>(deps_.db_pool, deps_.s3_client, nullptr,
                                                                            nullptr, nullptr, deps_.audit_publisher);
    }
    if (!deps_.object_assembly_engine && deps_.s3_client) {
        deps_.object_assembly_engine = std::make_shared<ObjectAssemblyEngine>(deps_.s3_client);
    }
    if (!deps_.finalization_service && deps_.object_assembly_engine && deps_.db_pool) {
        deps_.finalization_service =
            std::make_shared<FileFinalizationService>(deps_.db_pool, deps_.object_assembly_engine, nullptr, nullptr,
                                                      nullptr, nullptr, outbox_repo, deps_.audit_publisher);
    }
    if (!deps_.download_manager && deps_.s3_client && deps_.db_pool) {
        auto download_engine = std::make_shared<ChunkDownloadEngine>(deps_.s3_client);
        deps_.download_manager = std::make_shared<DownloadManager>(deps_.db_pool, download_engine, nullptr, nullptr,
                                                                   nullptr, deps_.audit_publisher);
    }
    if (!deps_.capability_manager && deps_.db_pool) {
        auto signer = std::make_shared<auth::crypto::Ed25519TokenSigner>("sc-files-v1");
        auto verifier = auth::crypto::Ed25519TokenVerifier::from_signer(*signer);
        deps_.capability_manager = std::make_shared<FileCapabilityManager>(deps_.db_pool, signer, std::move(verifier),
                                                                           nullptr, nullptr, deps_.audit_publisher);
    }
}

FilesServiceImpl::FilesServiceImpl(std::shared_ptr<db::FilesDbConnectionPool> db_pool,
                                   std::shared_ptr<storage::S3Client> s3_client, std::string expected_client_identity)
    : FilesServiceImpl(build_default_dependencies(std::move(db_pool), std::move(s3_client)),
                       std::move(expected_client_identity)) {}

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

// AUDIT-015-T03: Correlation & Tracing Extraction Helper
FilesCallerContext
FilesServiceImpl::extract_caller_context(const std::multimap<grpc::string_ref, grpc::string_ref>& client_metadata,
                                         const std::string& peer_identity, const std::string& fallback_user_id) const {
    FilesCallerContext ctx;
    auto get_meta = [&](const std::string& key) -> std::optional<std::string> {
        for (const auto& [k_ref, v_ref] : client_metadata) {
            std::string k(k_ref.data(), k_ref.size());
            for (char& c : k)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (k == key)
                return std::string(v_ref.data(), v_ref.size());
        }
        return std::nullopt;
    };

    std::string user_id = get_meta("x-user-id").value_or(fallback_user_id);
    if (user_id == "gateway") {
        user_id = fallback_user_id; // Never log impersonated gateway
    }
    ctx.user_id = user_id.empty() ? peer_identity : user_id;

    ctx.device_id = get_meta("x-device-id").value_or("unknown");

    std::string corr_id = get_meta("x-correlation-id").value_or("");
    if (corr_id.empty()) {
        corr_id = get_meta("x-request-id").value_or("");
    }
    if (corr_id.empty() || !is_valid_uuid(corr_id)) {
        corr_id = generate_uuid_v7();
    }
    ctx.correlation_id = corr_id;

    ctx.file_capability = get_meta("x-file-capability");
    if (!ctx.file_capability) {
        ctx.file_capability = get_meta("x-file-access-capability");
    }
    ctx.file_access_capability = get_meta("x-file-access-capability");

    return ctx;
}

// ==========================================
// 1. Create File Upload
// ==========================================

grpc::Status FilesServiceImpl::CreateFileUpload(grpc::ServerContext* context,
                                                const v1::CreateFileUploadRequest* request,
                                                v1::CreateFileUploadResponse* response) {
    const grpc::AuthContext* auth_ctx = (context != nullptr) ? context->auth_context().get() : nullptr;
    static const std::multimap<grpc::string_ref, grpc::string_ref> k_empty_metadata;
    const auto& metadata = (context != nullptr) ? context->client_metadata() : k_empty_metadata;
    return CreateFileUpload(auth_ctx, request, response, metadata);
}

grpc::Status
FilesServiceImpl::CreateFileUpload(const grpc::AuthContext* auth_ctx, const v1::CreateFileUploadRequest* request,
                                   v1::CreateFileUploadResponse* response,
                                   const std::multimap<grpc::string_ref, grpc::string_ref>& client_metadata) {
    std::string peer_identity;
    auto auth_status = check_peer_authorization(auth_ctx, "CreateFileUpload", peer_identity);
    if (!auth_status.ok()) {
        return auth_status;
    }

    if (!request || !response) {
        RpcScopeLogger logger("CreateFileUpload", peer_identity);
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid request or response pointer");
        logger.finish(status);
        return status;
    }

    auto caller_ctx = extract_caller_context(client_metadata, peer_identity, request->owner_user_id());
    ScopedFilesCallerContext caller_scope(caller_ctx);
    RpcScopeLogger logger("CreateFileUpload", caller_ctx.user_id);

    BulkheadPermit upload_permit;
    if (deps_.upload_bulkhead) {
        upload_permit = deps_.upload_bulkhead->acquire_with_default_timeout();
        if (!upload_permit) {
            auto status = grpc::Status(
                grpc::StatusCode::RESOURCE_EXHAUSTED,
                "Upload concurrency capacity exhausted (domain: " + deps_.upload_bulkhead->domain_name() + ")");
            logger.finish(status);
            return status;
        }
    }

    if (request->encrypted_size_bytes() > 0) {
        std::string size_err;
        if (!validate_file_transfer_size(request->encrypted_size_bytes(), deps_.max_file_transfer_bytes, size_err)) {
            auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, size_err);
            logger.finish(status);
            return status;
        }
    }

    if (!deps_.lifecycle_service) {
        auto status = grpc::Status(grpc::StatusCode::INTERNAL, "FileLifecycleService is not initialized");
        logger.finish(status);
        return status;
    }

    std::string target_file_id = request->file_id().empty() ? generate_uuid_v7() : request->file_id();

    const std::string resolved_algorithm =
        (request->encryption_version().empty() || request->encryption_version() == "v1")
            ? std::string(k_approved_encryption_algorithm)
            : request->encryption_version();

    CreateFileRequestDto dto{
        .file_id = target_file_id,
        .owner_user_id = request->owner_user_id(),
        .owner_device_id = request->owner_device_id(),
        .conversation_id =
            request->conversation_id().empty() ? std::nullopt : std::make_optional(request->conversation_id()),
        .encrypted_size_bytes = request->encrypted_size_bytes(),
        .expected_chunk_count = request->expected_chunk_count(),
        .encryption_algorithm = resolved_algorithm,
        .encrypted_filename = {},
        .encrypted_mime_type = std::nullopt,
        .metadata_nonce = {},
        .metadata_tag = {},
        .client_encryption_metadata_json = "{}",
        .retention_until = std::nullopt,
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

    if (deps_.upload_session_manager) {
        v1::CreateFileUploadRequest session_req = *request;
        session_req.set_file_id(target_file_id);
        auto session = deps_.upload_session_manager->create_session(session_req);
        if (session) {
            upload_id = session->upload_id;
            expiry_tp = session->expires_at;
            expires_ms = std::chrono::duration_cast<std::chrono::milliseconds>(expiry_tp.time_since_epoch()).count();
        } else {
            auto status = grpc::Status(grpc::StatusCode::INTERNAL, "Failed to create upload session");
            logger.finish(status);
            return status;
        }
    } else if (deps_.db_pool) {
        try {
            auto conn = deps_.db_pool->acquire();
            auto& default_conn = dynamic_cast<db::DefaultDbConnection&>(*conn);
            pqxx::work tx(default_conn.native_handle());
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
                .total_bytes = static_cast<int64_t>(dto.encrypted_size_bytes),
                .transferred_bytes = 0,
                .created_at = now,
                .updated_at = now,
                .expires_at = expiry_tp,
            };
            transfer_repo.create_transfer(transfer, tx);
            if (deps_.audit_publisher) {
                FilesAuditRecord record;
                record.event_type = "file.upload.initiated";
                record.severity = "INFO";
                record.actor_type = caller_ctx.user_id.empty() ? "SYSTEM" : "USER";
                record.actor_id = caller_ctx.user_id.empty() ? "system" : caller_ctx.user_id;
                record.target_type = "FILE";
                record.target_id = target_file_id;
                record.correlation_id = caller_ctx.correlation_id;
                record.metadata = {{"upload_id", upload_id},
                                   {"owner_device_id", request->owner_device_id()},
                                   {"expected_chunk_count", std::to_string(dto.expected_chunk_count)},
                                   {"encrypted_size_bytes", std::to_string(dto.encrypted_size_bytes)}};
                deps_.audit_publisher->publish_in_tx(record, tx);
            }
            tx.commit();
            if (deps_.audit_publisher) {
                deps_.audit_publisher->notify_relay();
            }
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
    static const std::multimap<grpc::string_ref, grpc::string_ref> k_empty_metadata;
    const auto& metadata = (context != nullptr) ? context->client_metadata() : k_empty_metadata;
    return UploadChunk(auth_ctx, request, response, metadata);
}

grpc::Status FilesServiceImpl::UploadChunk(const grpc::AuthContext* auth_ctx, const v1::UploadChunkRequest* request,
                                           v1::UploadChunkResponse* response,
                                           const std::multimap<grpc::string_ref, grpc::string_ref>& client_metadata) {
    std::string peer_identity;
    auto auth_status = check_peer_authorization(auth_ctx, "UploadChunk", peer_identity);
    if (!auth_status.ok()) {
        return auth_status;
    }

    auto caller_ctx = extract_caller_context(client_metadata, peer_identity);
    ScopedFilesCallerContext caller_scope(caller_ctx);
    RpcScopeLogger logger("UploadChunk", caller_ctx.user_id);

    if (!request || !response) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid request or response pointer");
        logger.finish(status);
        return status;
    }

    if (!is_valid_uuid(request->upload_id())) {
        auto status =
            grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "upload_id must be a valid RFC 4122 / UUIDv7 string");
        logger.finish(status);
        return status;
    }

    BulkheadPermit upload_permit;
    if (deps_.upload_bulkhead) {
        upload_permit = deps_.upload_bulkhead->acquire_with_default_timeout();
        if (!upload_permit) {
            auto status = grpc::Status(
                grpc::StatusCode::RESOURCE_EXHAUSTED,
                "Upload concurrency capacity exhausted (domain: " + deps_.upload_bulkhead->domain_name() + ")");
            logger.finish(status);
            return status;
        }
    }

    size_t chunk_bytes =
        request->chunk_size_bytes() > 0 ? request->chunk_size_bytes() : request->encrypted_data().size();
    std::string chunk_size_err;
    if (!validate_chunk_request_size(chunk_bytes, deps_.max_chunk_request_bytes, chunk_size_err)) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, chunk_size_err);
        logger.finish(status);
        return status;
    }

    MemoryBufferReservation mem_reservation;
    if (deps_.memory_tracker) {
        mem_reservation = deps_.memory_tracker->try_reserve(chunk_bytes);
        if (!mem_reservation) {
            auto status = grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED,
                                       "Global memory buffer budget exhausted for incoming chunk");
            logger.finish(status);
            return status;
        }
    }

    ChunkPayloadDto dto{
        .upload_id = request->upload_id(),
        .chunk_index = request->chunk_index(),
        .encrypted_data = request->encrypted_data(),
        .chunk_size_bytes = request->chunk_size_bytes(),
        .claimed_sha256 = request->ciphertext_sha256(),
    };

    uint32_t total_chunks = 0;
    uint64_t total_bytes = 0;
    std::string resolved_file_id;

    if (deps_.upload_session_manager) {
        try {
            auto progress = deps_.upload_session_manager->get_transfer_progress(dto.upload_id);
            total_chunks = progress.total_chunks;
            total_bytes = static_cast<uint64_t>(progress.total_bytes);
            resolved_file_id = progress.file_id;

            if (progress.status == TransferStatus::Cancelled) {
                auto status = grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, "Upload session has been cancelled");
                logger.finish(status);
                return status;
            }
            if (progress.status == TransferStatus::Expired || progress.is_expired) {
                auto status = grpc::Status(grpc::StatusCode::DEADLINE_EXCEEDED, "Upload session lease expired");
                logger.finish(status);
                return status;
            }
        } catch (const TransferNotFoundException& ex) {
            auto status = grpc::Status(grpc::StatusCode::NOT_FOUND, ex.what());
            logger.finish(status);
            return status;
        } catch (const TransferCancelledException& ex) {
            auto status = grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, ex.what());
            logger.finish(status);
            return status;
        } catch (const TransferExpiredException& ex) {
            auto status = grpc::Status(grpc::StatusCode::DEADLINE_EXCEEDED, ex.what());
            logger.finish(status);
            return status;
        } catch (const std::exception& ex) {
            auto status = grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
            logger.finish(status);
            return status;
        }
    }

    if (total_chunks > 0) {
        auto val_result = validate_chunk_payload(dto, total_chunks, total_bytes);
        if (!val_result.is_valid) {
            if (deps_.audit_publisher && val_result.error_message.find("digest mismatch") != std::string::npos) {
                const auto target =
                    resolve_upload_audit_target(deps_.upload_session_manager, dto.upload_id, resolved_file_id);
                FilesAuditRecord record;
                record.event_type = "file.chunk.integrity_failed";
                record.severity = "SECURITY";
                record.actor_type = "USER";
                record.actor_id = caller_ctx.user_id;
                record.target_type = target.first;
                record.target_id = target.second;
                record.correlation_id = caller_ctx.correlation_id;
                record.metadata = {{"upload_id", dto.upload_id},
                                   {"chunk_index", std::to_string(dto.chunk_index)},
                                   {"reason", "sha256_mismatch"}};
                deps_.audit_publisher->publish_autonomous(record);
            }
            auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, val_result.error_message);
            logger.finish(status);
            return status;
        }
    } else {
        if (dto.chunk_size_bytes != dto.encrypted_data.size()) {
            auto status =
                grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "chunk_size_bytes does not match payload size");
            logger.finish(status);
            return status;
        }
        if (!is_valid_sha256_hex(dto.claimed_sha256)) {
            auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "claimed_sha256 format is invalid");
            logger.finish(status);
            return status;
        }
        std::string computed_hash = compute_sha256_hex(dto.encrypted_data);
        if (computed_hash != dto.claimed_sha256) {
            // AUDIT-015-T03: Stage autonomous event E07 (file.chunk.integrity_failed)
            if (deps_.audit_publisher) {
                const auto target =
                    resolve_upload_audit_target(deps_.upload_session_manager, dto.upload_id, resolved_file_id);
                FilesAuditRecord record;
                record.event_type = "file.chunk.integrity_failed";
                record.severity = "SECURITY";
                record.actor_type = "USER";
                record.actor_id = caller_ctx.user_id;
                record.target_type = target.first;
                record.target_id = target.second;
                record.correlation_id = caller_ctx.correlation_id;
                record.metadata = {{"upload_id", dto.upload_id},
                                   {"chunk_index", std::to_string(dto.chunk_index)},
                                   {"reason", "sha256_mismatch"}};
                deps_.audit_publisher->publish_autonomous(record);
            }

            auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "SHA-256 digest mismatch");
            logger.finish(status);
            return status;
        }
    }

    if (!deps_.chunk_storage_service) {
        auto status = grpc::Status(grpc::StatusCode::INTERNAL, "ChunkStorageService is not configured");
        logger.finish(status);
        return status;
    }

    try {
        auto store_result = deps_.chunk_storage_service->store_chunk(dto, caller_ctx.user_id);
        response->set_upload_id(dto.upload_id);
        response->set_chunk_index(dto.chunk_index);
        response->set_accepted(store_result.accepted);
        response->set_received_sha256(store_result.received_sha256);

        if (deps_.upload_session_manager) {
            deps_.upload_session_manager->record_chunk_upload(dto.upload_id, dto.chunk_index,
                                                              store_result.received_sha256);
        }

        auto status = grpc::Status::OK;
        logger.finish(status);
        return status;
    } catch (const ChunkIntegrityException& ex) {
        // AUDIT-015-T03: Record autonomous exception E07
        if (deps_.audit_publisher) {
            const auto target =
                resolve_upload_audit_target(deps_.upload_session_manager, dto.upload_id, resolved_file_id);
            FilesAuditRecord record;
            record.event_type = "file.chunk.integrity_failed";
            record.severity = "SECURITY";
            record.actor_type = "USER";
            record.actor_id = caller_ctx.user_id;
            record.target_type = target.first;
            record.target_id = target.second;
            record.correlation_id = caller_ctx.correlation_id;
            record.metadata = {{"upload_id", dto.upload_id},
                               {"chunk_index", std::to_string(dto.chunk_index)},
                               {"reason", "chunk_conflict"}};
            deps_.audit_publisher->publish_autonomous(record);
        }
        auto status = grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
                                   std::string("Chunk content conflicts with previously accepted chunk: ") + ex.what());
        logger.finish(status);
        return status;
    } catch (const UnauthorizedTransferException& ex) {
        // AUDIT-015-T03: E12 Unauthorized Access attempt
        if (deps_.audit_publisher) {
            const auto target =
                resolve_upload_audit_target(deps_.upload_session_manager, dto.upload_id, resolved_file_id);
            FilesAuditRecord record;
            record.event_type = "file.access.denied";
            record.severity = "SECURITY";
            record.actor_type = "USER";
            record.actor_id = caller_ctx.user_id;
            record.target_type = target.first;
            record.target_id = target.second;
            record.correlation_id = caller_ctx.correlation_id;
            record.metadata = {{"operation", "UploadChunk"},
                               {"upload_id", dto.upload_id},
                               {"device_id", caller_ctx.device_id},
                               {"reason", ex.what()}};
            deps_.audit_publisher->publish_autonomous(record);
        }
        auto status = grpc::Status(grpc::StatusCode::PERMISSION_DENIED, ex.what());
        logger.finish(status);
        return status;
    } catch (const TransferNotFoundException& ex) {
        auto status = grpc::Status(grpc::StatusCode::NOT_FOUND, ex.what());
        logger.finish(status);
        return status;
    } catch (const TransferExpiredException& ex) {
        auto status = grpc::Status(grpc::StatusCode::DEADLINE_EXCEEDED, ex.what());
        logger.finish(status);
        return status;
    } catch (const TransferCancelledException& ex) {
        auto status = grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, ex.what());
        logger.finish(status);
        return status;
    } catch (const std::exception& ex) {
        auto status = grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
        logger.finish(status);
        return status;
    }
}

// ==========================================
// 3. Finalize File Upload
// ==========================================

grpc::Status FilesServiceImpl::FinalizeFileUpload(grpc::ServerContext* context,
                                                  const v1::FinalizeFileUploadRequest* request,
                                                  v1::FinalizeFileUploadResponse* response) {
    const grpc::AuthContext* auth_ctx = (context != nullptr) ? context->auth_context().get() : nullptr;
    static const std::multimap<grpc::string_ref, grpc::string_ref> k_empty_metadata;
    const auto& metadata = (context != nullptr) ? context->client_metadata() : k_empty_metadata;
    return FinalizeFileUpload(auth_ctx, request, response, metadata);
}

grpc::Status
FilesServiceImpl::FinalizeFileUpload(const grpc::AuthContext* auth_ctx, const v1::FinalizeFileUploadRequest* request,
                                     v1::FinalizeFileUploadResponse* response,
                                     const std::multimap<grpc::string_ref, grpc::string_ref>& client_metadata) {
    std::string peer_identity;
    auto auth_status = check_peer_authorization(auth_ctx, "FinalizeFileUpload", peer_identity);
    if (!auth_status.ok()) {
        return auth_status;
    }

    auto caller_ctx = extract_caller_context(client_metadata, peer_identity);
    ScopedFilesCallerContext caller_scope(caller_ctx);
    RpcScopeLogger logger("FinalizeFileUpload", caller_ctx.user_id);

    if (!request || !response) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid request or response pointer");
        logger.finish(status);
        return status;
    }

    if (!is_valid_uuid(request->upload_id())) {
        auto status =
            grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "upload_id must be a valid RFC 4122 / UUIDv7 string");
        logger.finish(status);
        return status;
    }

    if (!is_valid_uuid(request->file_id())) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid file_id format");
        logger.finish(status);
        return status;
    }

    BulkheadPermit upload_permit;
    if (deps_.upload_bulkhead) {
        upload_permit = deps_.upload_bulkhead->acquire_with_default_timeout();
        if (!upload_permit) {
            auto status = grpc::Status(
                grpc::StatusCode::RESOURCE_EXHAUSTED,
                "Upload concurrency capacity exhausted (domain: " + deps_.upload_bulkhead->domain_name() + ")");
            logger.finish(status);
            return status;
        }
    }

    if (!deps_.finalization_service) {
        auto status = grpc::Status(grpc::StatusCode::UNAVAILABLE, "Finalization service uninitialized");
        logger.finish(status);
        return status;
    }

    FinalizeUploadRequestDto dto{
        .upload_id = request->upload_id(),
        .file_id = request->file_id(),
        .caller_user_id = caller_ctx.user_id,
        .expected_ciphertext_sha256 = request->expected_ciphertext_sha256(),
    };

    const auto& finalization_service_ref = *deps_.finalization_service;
    const bool is_real_finalization_service = (typeid(finalization_service_ref) == typeid(FileFinalizationService));
    auto emit_fallback_finalization_failure = [&](std::string_view severity, std::string_view reason) {
        if (!deps_.audit_publisher || is_real_finalization_service) {
            return;
        }
        FilesAuditRecord record;
        record.event_type = "file.finalization.failed";
        record.severity = std::string(severity);
        record.actor_type = "USER";
        record.actor_id = caller_ctx.user_id;
        record.target_type = "FILE";
        record.target_id = request->file_id();
        record.correlation_id = caller_ctx.correlation_id;
        record.metadata = {{"upload_id", dto.upload_id}, {"reason", std::string(reason)}};
        deps_.audit_publisher->publish_autonomous(record);
    };

    try {
        auto result = deps_.finalization_service->finalize_file_upload(dto);
        response->set_file_id(result.file_id);
        response->set_lifecycle_state(v1::FILE_LIFECYCLE_STATE_AVAILABLE);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(result.available_at.time_since_epoch()).count();
        response->set_available_at_unix_ms(ms);

        auto status = grpc::Status::OK;
        logger.finish(status);
        return status;
    } catch (const EntityNotFoundException& ex) {
        auto status = grpc::Status(grpc::StatusCode::NOT_FOUND, ex.what());
        logger.finish(status);
        return status;
    } catch (const FinalizationPreconditionException& ex) {
        emit_fallback_finalization_failure("WARNING", "precondition_failed");
        auto status = grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, ex.what());
        logger.finish(status);
        return status;
    } catch (const ChunkIntegrityException& ex) {
        emit_fallback_finalization_failure("SECURITY", "chunk_hash_tamper");
        auto status = grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, ex.what());
        logger.finish(status);
        return status;
    } catch (const storage::S3IntegrityException& ex) {
        emit_fallback_finalization_failure("SECURITY", "chunk_hash_tamper");
        auto status = grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, ex.what());
        logger.finish(status);
        return status;
    } catch (const storage::S3ObjectNotFoundException& ex) {
        emit_fallback_finalization_failure("WARNING", "s3_error");
        auto status = grpc::Status(grpc::StatusCode::NOT_FOUND, ex.what());
        logger.finish(status);
        return status;
    } catch (const storage::S3AuthenticationException& ex) {
        emit_fallback_finalization_failure("WARNING", "s3_error");
        auto status = grpc::Status(grpc::StatusCode::PERMISSION_DENIED, ex.what());
        logger.finish(status);
        return status;
    } catch (const storage::S3ConnectionException& ex) {
        emit_fallback_finalization_failure("WARNING", "s3_error");
        auto status = grpc::Status(grpc::StatusCode::DEADLINE_EXCEEDED, ex.what());
        logger.finish(status);
        return status;
    } catch (const std::invalid_argument& ex) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, ex.what());
        logger.finish(status);
        return status;
    } catch (const std::exception& ex) {
        auto status = grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
        logger.finish(status);
        return status;
    }
}

// ==========================================
// 4. Get File Metadata
// ==========================================

grpc::Status FilesServiceImpl::GetFileMetadata(grpc::ServerContext* context, const v1::GetFileMetadataRequest* request,
                                               v1::GetFileMetadataResponse* response) {
    const grpc::AuthContext* auth_ctx = (context != nullptr) ? context->auth_context().get() : nullptr;
    static const std::multimap<grpc::string_ref, grpc::string_ref> k_empty_metadata;
    const auto& metadata = (context != nullptr) ? context->client_metadata() : k_empty_metadata;
    return GetFileMetadata(auth_ctx, request, response, metadata);
}

grpc::Status
FilesServiceImpl::GetFileMetadata(const grpc::AuthContext* auth_ctx, const v1::GetFileMetadataRequest* request,
                                  v1::GetFileMetadataResponse* response,
                                  const std::multimap<grpc::string_ref, grpc::string_ref>& client_metadata) {
    std::string peer_identity;
    auto auth_status = check_peer_authorization(auth_ctx, "GetFileMetadata", peer_identity);
    if (!auth_status.ok()) {
        return auth_status;
    }

    auto caller_ctx = extract_caller_context(client_metadata, peer_identity);
    ScopedFilesCallerContext caller_scope(caller_ctx);
    RpcScopeLogger logger("GetFileMetadata", caller_ctx.user_id);

    if (!request || !response) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid request or response pointer");
        logger.finish(status);
        return status;
    }

    BulkheadPermit metadata_permit;
    if (deps_.metadata_bulkhead) {
        metadata_permit = deps_.metadata_bulkhead->acquire_with_default_timeout();
        if (!metadata_permit) {
            auto status = grpc::Status(
                grpc::StatusCode::RESOURCE_EXHAUSTED,
                "Metadata concurrency capacity exhausted (domain: " + deps_.metadata_bulkhead->domain_name() + ")");
            logger.finish(status);
            return status;
        }
    }

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
        summary_opt = deps_.lifecycle_service->get_file_metadata(request->file_id(), caller_ctx.user_id);
    } catch (const UnauthorizedFileAccessException& ex) {
        if (deps_.audit_publisher) {
            FilesAuditRecord record;
            record.event_type = "file.access.denied";
            record.severity = "SECURITY";
            record.actor_type = "USER";
            record.actor_id = caller_ctx.user_id;
            record.target_type = "FILE";
            record.target_id = request->file_id();
            record.correlation_id = caller_ctx.correlation_id;
            record.metadata = {
                {"operation", "GetFileMetadata"}, {"device_id", caller_ctx.device_id}, {"reason", ex.what()}};
            deps_.audit_publisher->publish_autonomous(record);
        }
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
    static const std::multimap<grpc::string_ref, grpc::string_ref> k_empty_metadata;
    const auto& metadata = (context != nullptr) ? context->client_metadata() : k_empty_metadata;
    return DownloadChunk(auth_ctx, request, response, metadata);
}

grpc::Status FilesServiceImpl::DownloadChunk(const grpc::AuthContext* auth_ctx, const v1::DownloadChunkRequest* request,
                                             v1::DownloadChunkResponse* response,
                                             const std::multimap<grpc::string_ref, grpc::string_ref>& client_metadata) {
    std::string peer_identity;
    auto auth_status = check_peer_authorization(auth_ctx, "DownloadChunk", peer_identity);
    if (!auth_status.ok()) {
        return auth_status;
    }

    auto caller_ctx = extract_caller_context(client_metadata, peer_identity);
    ScopedFilesCallerContext caller_scope(caller_ctx);
    RpcScopeLogger logger("DownloadChunk", caller_ctx.user_id);

    if (!request || !response) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid request or response pointer");
        logger.finish(status);
        return status;
    }

    BulkheadPermit download_permit;
    if (deps_.download_bulkhead) {
        download_permit = deps_.download_bulkhead->acquire_with_default_timeout();
        if (!download_permit) {
            auto status = grpc::Status(
                grpc::StatusCode::RESOURCE_EXHAUSTED,
                "Download concurrency capacity exhausted (domain: " + deps_.download_bulkhead->domain_name() + ")");
            logger.finish(status);
            return status;
        }
    }

    if (!is_valid_uuid(request->file_id())) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid file_id format: " + request->file_id());
        logger.finish(status);
        return status;
    }

    // AUDIT-015-T03: Direct context-driven authorization evaluation
    if (deps_.capability_manager && caller_ctx.file_capability) {
        const bool is_real_cap_mgr =
            (dynamic_cast<const FileCapabilityManager*>(deps_.capability_manager.get()) != nullptr);
        auto emit_fallback_cap_rejected = [&](std::string_view reason) {
            if (!deps_.audit_publisher || is_real_cap_mgr) {
                return;
            }
            FilesAuditRecord record;
            record.event_type = "file.capability.rejected";
            record.severity = "SECURITY";
            record.actor_type = "USER";
            record.actor_id = caller_ctx.user_id;
            record.target_type = "FILE";
            record.target_id = request->file_id();
            record.correlation_id = caller_ctx.correlation_id;
            record.metadata = {{"reason", std::string(reason)},
                               {"requested_operation", std::string(to_string(FileCapabilityOperation::Read))},
                               {"device_id", caller_ctx.device_id}};
            deps_.audit_publisher->publish_autonomous(record);
        };

        try {
            deps_.capability_manager->authorize_capability(*caller_ctx.file_capability, caller_ctx.user_id,
                                                           caller_ctx.device_id, request->file_id(),
                                                           FileCapabilityOperation::Read, 0);
        } catch (const InvalidCapabilityException& ex) {
            emit_fallback_cap_rejected("invalid_signature");
            auto status = grpc::Status(grpc::StatusCode::UNAUTHENTICATED, ex.what());
            logger.finish(status);
            return status;
        } catch (const UnauthorizedFileAccessException& ex) {
            emit_fallback_cap_rejected("scope_mismatch");
            auto status = grpc::Status(grpc::StatusCode::PERMISSION_DENIED, ex.what());
            logger.finish(status);
            return status;
        } catch (const std::exception& ex) {
            emit_fallback_cap_rejected("invalid_capability");
            auto status = grpc::Status(grpc::StatusCode::PERMISSION_DENIED, ex.what());
            logger.finish(status);
            return status;
        }
    }

    if (!deps_.download_manager) {
        auto status = grpc::Status(grpc::StatusCode::UNAVAILABLE, "DownloadManager is not configured");
        logger.finish(status);
        return status;
    }

    try {
        auto chunk_res = deps_.download_manager->get_chunk_versioned(request->file_id(), 0, request->chunk_index(),
                                                                     caller_ctx.user_id);

        std::string chunk_size_err;
        if (!validate_chunk_request_size(chunk_res.chunk_size_bytes, deps_.max_chunk_request_bytes, chunk_size_err)) {
            auto status = grpc::Status(grpc::StatusCode::OUT_OF_RANGE, chunk_size_err);
            logger.finish(status);
            return status;
        }

        MemoryBufferReservation mem_reservation;
        if (deps_.memory_tracker) {
            mem_reservation = deps_.memory_tracker->try_reserve(chunk_res.chunk_size_bytes);
            if (!mem_reservation) {
                auto status = grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED,
                                           "Global memory buffer budget exhausted during chunk download");
                logger.finish(status);
                return status;
            }
        }

        response->set_file_id(chunk_res.file_id);
        response->set_chunk_index(chunk_res.chunk_index);
        response->set_encrypted_data(chunk_res.encrypted_data);
        response->set_chunk_size_bytes(chunk_res.chunk_size_bytes);
        response->set_ciphertext_sha256(chunk_res.ciphertext_sha256);

        auto status = grpc::Status::OK;
        logger.finish(status);
        return status;
    } catch (const UnauthorizedFileAccessException& ex) {
        if (deps_.audit_publisher) {
            FilesAuditRecord record;
            record.event_type = "file.access.denied";
            record.severity = "SECURITY";
            record.actor_type = "USER";
            record.actor_id = caller_ctx.user_id;
            record.target_type = "FILE";
            record.target_id = request->file_id();
            record.correlation_id = caller_ctx.correlation_id;
            record.metadata = {
                {"operation", "DownloadChunk"}, {"device_id", caller_ctx.device_id}, {"reason", ex.what()}};
            deps_.audit_publisher->publish_autonomous(record);
        }
        auto status = grpc::Status(grpc::StatusCode::PERMISSION_DENIED, ex.what());
        logger.finish(status);
        return status;
    } catch (const EntityNotFoundException& ex) {
        auto status = grpc::Status(grpc::StatusCode::NOT_FOUND, ex.what());
        logger.finish(status);
        return status;
    } catch (const FileNotFoundException& ex) {
        auto status = grpc::Status(grpc::StatusCode::NOT_FOUND, ex.what());
        logger.finish(status);
        return status;
    } catch (const InvalidDownloadPreconditionException& ex) {
        auto status = grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, ex.what());
        logger.finish(status);
        return status;
    } catch (const std::out_of_range& ex) {
        auto status = grpc::Status(grpc::StatusCode::OUT_OF_RANGE, ex.what());
        logger.finish(status);
        return status;
    } catch (const storage::S3ObjectNotFoundException& ex) {
        auto status = grpc::Status(grpc::StatusCode::NOT_FOUND, ex.what());
        logger.finish(status);
        return status;
    } catch (const storage::S3ConnectionException& ex) {
        auto status = grpc::Status(grpc::StatusCode::DEADLINE_EXCEEDED, ex.what());
        logger.finish(status);
        return status;
    } catch (const storage::S3AuthenticationException& ex) {
        auto status = grpc::Status(grpc::StatusCode::PERMISSION_DENIED, ex.what());
        logger.finish(status);
        return status;
    } catch (const std::invalid_argument& ex) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, ex.what());
        logger.finish(status);
        return status;
    } catch (const std::exception& ex) {
        auto status = grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
        logger.finish(status);
        return status;
    }
}

// ==========================================
// 6. Cancel File Upload
// ==========================================

grpc::Status FilesServiceImpl::CancelFileUpload(grpc::ServerContext* context,
                                                const v1::CancelFileUploadRequest* request,
                                                v1::CancelFileUploadResponse* response) {
    const grpc::AuthContext* auth_ctx = (context != nullptr) ? context->auth_context().get() : nullptr;
    static const std::multimap<grpc::string_ref, grpc::string_ref> k_empty_metadata;
    const auto& metadata = (context != nullptr) ? context->client_metadata() : k_empty_metadata;
    return CancelFileUpload(auth_ctx, request, response, metadata);
}

grpc::Status
FilesServiceImpl::CancelFileUpload(const grpc::AuthContext* auth_ctx, const v1::CancelFileUploadRequest* request,
                                   v1::CancelFileUploadResponse* response,
                                   const std::multimap<grpc::string_ref, grpc::string_ref>& client_metadata) {
    std::string peer_identity;
    auto auth_status = check_peer_authorization(auth_ctx, "CancelFileUpload", peer_identity);
    if (!auth_status.ok()) {
        return auth_status;
    }

    auto caller_ctx = extract_caller_context(client_metadata, peer_identity);
    ScopedFilesCallerContext caller_scope(caller_ctx);
    RpcScopeLogger logger("CancelFileUpload", caller_ctx.user_id);

    if (!request || !response) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid request or response pointer");
        logger.finish(status);
        return status;
    }

    BulkheadPermit metadata_permit;
    if (deps_.metadata_bulkhead) {
        metadata_permit = deps_.metadata_bulkhead->acquire_with_default_timeout();
        if (!metadata_permit) {
            auto status = grpc::Status(
                grpc::StatusCode::RESOURCE_EXHAUSTED,
                "Metadata concurrency capacity exhausted (domain: " + deps_.metadata_bulkhead->domain_name() + ")");
            logger.finish(status);
            return status;
        }
    }

    if (!is_valid_uuid(request->upload_id())) {
        auto status =
            grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "upload_id must be a valid RFC 4122 / UUIDv7 string");
        logger.finish(status);
        return status;
    }

    if (!deps_.upload_session_manager) {
        auto status = grpc::Status(grpc::StatusCode::INTERNAL, "UploadSessionManager is not configured");
        logger.finish(status);
        return status;
    }

    bool cancelled = deps_.upload_session_manager->cancel_session(request->upload_id(), request->reason());
    if (!cancelled) {
        auto status = grpc::Status(grpc::StatusCode::NOT_FOUND, "Upload session not found: " + request->upload_id());
        logger.finish(status);
        return status;
    }

    response->set_upload_id(request->upload_id());
    response->set_status(v1::TRANSFER_STATUS_CANCELLED);

    auto status = grpc::Status::OK;
    logger.finish(status);
    return status;
}

// ==========================================
// 7. Delete File
// ==========================================

grpc::Status FilesServiceImpl::DeleteFile(grpc::ServerContext* context, const v1::DeleteFileRequest* request,
                                          v1::DeleteFileResponse* response) {
    const grpc::AuthContext* auth_ctx = (context != nullptr) ? context->auth_context().get() : nullptr;
    static const std::multimap<grpc::string_ref, grpc::string_ref> k_empty_metadata;
    const auto& metadata = (context != nullptr) ? context->client_metadata() : k_empty_metadata;
    return DeleteFile(auth_ctx, request, response, metadata);
}

grpc::Status FilesServiceImpl::DeleteFile(const grpc::AuthContext* auth_ctx, const v1::DeleteFileRequest* request,
                                          v1::DeleteFileResponse* response,
                                          const std::multimap<grpc::string_ref, grpc::string_ref>& client_metadata) {
    std::string peer_identity;
    auto auth_status = check_peer_authorization(auth_ctx, "DeleteFile", peer_identity);
    if (!auth_status.ok()) {
        return auth_status;
    }

    auto caller_ctx = extract_caller_context(client_metadata, peer_identity);
    ScopedFilesCallerContext caller_scope(caller_ctx);
    RpcScopeLogger logger("DeleteFile", caller_ctx.user_id);

    if (!request || !response) {
        auto status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid request or response pointer");
        logger.finish(status);
        return status;
    }

    BulkheadPermit metadata_permit;
    if (deps_.metadata_bulkhead) {
        metadata_permit = deps_.metadata_bulkhead->acquire_with_default_timeout();
        if (!metadata_permit) {
            auto status = grpc::Status(
                grpc::StatusCode::RESOURCE_EXHAUSTED,
                "Metadata concurrency capacity exhausted (domain: " + deps_.metadata_bulkhead->domain_name() + ")");
            logger.finish(status);
            return status;
        }
    }

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
        deps_.lifecycle_service->delete_file(request->file_id(), caller_ctx.user_id, "Client requested deletion");
    } catch (const FileNotFoundException& ex) {
        auto status = grpc::Status(grpc::StatusCode::NOT_FOUND, ex.what());
        logger.finish(status);
        return status;
    } catch (const UnauthorizedFileAccessException& ex) {
        if (deps_.audit_publisher) {
            FilesAuditRecord record;
            record.event_type = "file.access.denied";
            record.severity = "SECURITY";
            record.actor_type = "USER";
            record.actor_id = caller_ctx.user_id;
            record.target_type = "FILE";
            record.target_id = request->file_id();
            record.correlation_id = caller_ctx.correlation_id;
            record.metadata = {{"operation", "DeleteFile"}, {"device_id", caller_ctx.device_id}, {"reason", ex.what()}};
            deps_.audit_publisher->publish_autonomous(record);
        }
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
