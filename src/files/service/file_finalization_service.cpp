#include "files/service/file_finalization_service.hpp"

#include "files/db/files_connection_pool.hpp"
#include "files/domain/metadata_validator.hpp"
#include "files/service/files_caller_context.hpp"
#include "files/storage/s3_exceptions.hpp"

#include <iostream>

namespace securecloud::files::service {

namespace {

[[nodiscard]] std::string resolve_finalization_correlation_id() {
    if (const auto ctx = current_files_caller_context(); ctx && !ctx->correlation_id.empty()) {
        return ctx->correlation_id;
    }
    return generate_uuid_v7();
}

void emit_finalization_failed(const std::shared_ptr<FilesAuditEventPublisher>& publisher, const std::string& file_id,
                              const std::string& actor_id, const std::string& upload_id, std::string_view severity,
                              std::string_view reason, size_t accepted_chunks, int32_t expected_chunks) noexcept {
    if (!publisher) {
        return;
    }
    FilesAuditRecord record;
    record.event_type = "file.finalization.failed";
    record.severity = std::string(severity);
    record.actor_type = actor_id.empty() || actor_id == "system" ? "SYSTEM" : "USER";
    record.actor_id = actor_id.empty() ? "system" : actor_id;
    record.target_type = file_id.empty() ? "SERVICE" : "FILE";
    record.target_id = file_id.empty() ? "files" : file_id;
    record.correlation_id = resolve_finalization_correlation_id();
    record.metadata = {{"upload_id", upload_id},
                       {"reason", std::string(reason)},
                       {"accepted_chunks", std::to_string(accepted_chunks)},
                       {"expected_chunks", std::to_string(std::max<int32_t>(0, expected_chunks))}};
    publisher->publish_autonomous(record);
}

} // namespace

FileFinalizationService::FileFinalizationService(
    std::shared_ptr<db::FilesDbConnectionPool> pool, std::shared_ptr<ObjectAssemblyEngine> assembly_engine,
    std::shared_ptr<FileTransferRepository> transfer_repo, std::shared_ptr<FileRepository> file_repo,
    std::shared_ptr<FileVersionRepository> version_repo, std::shared_ptr<FileChunkRepository> chunk_repo,
    std::shared_ptr<FilesOutboxRepository> outbox_repo, std::shared_ptr<FilesAuditEventPublisher> audit_publisher)
    : pool_(std::move(pool)), assembly_engine_(std::move(assembly_engine)), transfer_repo_(std::move(transfer_repo)),
      file_repo_(std::move(file_repo)), version_repo_(std::move(version_repo)), chunk_repo_(std::move(chunk_repo)),
      outbox_repo_(std::move(outbox_repo)), audit_publisher_(std::move(audit_publisher)) {
    if (!transfer_repo_ && pool_) {
        transfer_repo_ = std::make_shared<FileTransferRepository>(pool_);
    }
    if (!file_repo_ && pool_) {
        file_repo_ = std::make_shared<FileRepository>(pool_);
    }
    if (!version_repo_ && pool_) {
        version_repo_ = std::make_shared<FileVersionRepository>(pool_);
    }
    if (!chunk_repo_ && pool_) {
        chunk_repo_ = std::make_shared<FileChunkRepository>(pool_);
    }
    if (!outbox_repo_ && pool_) {
        outbox_repo_ = std::make_shared<FilesOutboxRepository>(pool_);
    }
    if (!audit_publisher_ && outbox_repo_) {
        audit_publisher_ = std::make_shared<FilesAuditEventPublisher>(outbox_repo_);
    }
}

FinalizeUploadResultDto FileFinalizationService::finalize_file_upload(const FinalizeUploadRequestDto& request) {
    if (request.upload_id.empty()) {
        throw FinalizationPreconditionException("upload_id must not be empty");
    }

    if (!assembly_engine_) {
        throw std::runtime_error("ObjectAssemblyEngine is uninitialized");
    }

    if (!pool_) {
        throw std::runtime_error("Database connection pool is uninitialized");
    }

    std::shared_ptr<std::mutex> session_lock;
    {
        std::lock_guard<std::mutex> lock(session_locks_mutex_);
        auto& ptr = session_locks_[request.upload_id];
        if (!ptr) {
            ptr = std::make_shared<std::mutex>();
        }
        session_lock = ptr;
    }
    std::lock_guard<std::mutex> lock(*session_lock);

    struct LockCleaner {
        std::mutex& map_mutex;
        std::unordered_map<std::string, std::shared_ptr<std::mutex>>& map;
        std::string id;
        std::shared_ptr<std::mutex> lock_ptr;

        ~LockCleaner() {
            lock_ptr.reset();
            std::lock_guard<std::mutex> lk(map_mutex);
            auto it = map.find(id);
            if (it != map.end() && it->second.use_count() <= 1) {
                map.erase(it);
            }
        }
    } cleaner{session_locks_mutex_, session_locks_, request.upload_id, session_lock};

    auto conn = pool_->acquire();

    auto& default_conn = dynamic_cast<securecloud::files::db::DefaultDbConnection&>(*conn);
    auto tx = std::make_unique<pqxx::work>(default_conn.native_handle());
    auto release_db = [&]() {
        if (tx) {
            tx->abort();
            tx.reset();
        }
        conn = db::PooledConnection{};
    };

    // 1. Fetch transfer session
    auto transfer_opt = transfer_repo_->find_by_id(request.upload_id, *tx);
    if (!transfer_opt) {
        tx->abort();
        throw EntityNotFoundException("Transfer session not found: " + request.upload_id);
    }

    // 2. Validate file_id association if specified in request
    if (!request.file_id.empty() && request.file_id != transfer_opt->file_id) {
        tx->abort();
        throw FinalizationPreconditionException("Request file_id (" + request.file_id +
                                                ") does not match transfer session file_id (" + transfer_opt->file_id +
                                                ")");
    }

    // 3. Fetch file entity
    auto file_opt = file_repo_->find_by_id(transfer_opt->file_id, *tx);
    if (!file_opt) {
        tx->abort();
        throw EntityNotFoundException("File record not found: " + transfer_opt->file_id);
    }

    // 4. Verify caller authorization
    if (!request.caller_user_id.empty() && file_opt->owner_user_id != request.caller_user_id) {
        tx->abort();
        throw FinalizationPreconditionException("Caller user ID does not match file owner ID");
    }

    // 5. Anti-split-brain Idempotency Check: if transfer is already completed or file is already available
    if (transfer_opt->status == TransferStatus::Completed || file_opt->status == FileStatus::Available) {
        auto active_ver = version_repo_->find_active_version(file_opt->file_id, *tx);
        if (active_ver) {
            tx->commit();
            tx.reset();
            conn = db::PooledConnection{};
            return FinalizeUploadResultDto{.file_id = file_opt->file_id,
                                           .version_number = active_ver->version_number,
                                           .total_bytes = static_cast<uint64_t>(active_ver->encrypted_size),
                                           .checksum_sha256 = active_ver->checksum_sha256,
                                           .available_at = active_ver->created_at,
                                           .is_idempotent_replay = true};
        }
    }

    // 6. Reject invalid terminal transfer states
    if (transfer_opt->status == TransferStatus::Cancelled) {
        tx->abort();
        throw FinalizationPreconditionException("Cannot finalize a cancelled transfer session");
    }
    if (transfer_opt->status == TransferStatus::Expired) {
        tx->abort();
        throw FinalizationPreconditionException("Cannot finalize an expired transfer session");
    }
    if (transfer_opt->status == TransferStatus::Failed) {
        tx->abort();
        throw FinalizationPreconditionException("Cannot finalize a failed transfer session");
    }

    // 7. Transition states to FINALIZING
    transfer_repo_->update_status(transfer_opt->transfer_id, TransferStatus::Finalizing, *tx);
    file_repo_->update_status(file_opt->file_id, file_opt->status, FileStatus::Finalizing, *tx);

    // 8. Load chunks and perform authoritative precondition validation
    auto chunks = chunk_repo_->list_chunks_for_transfer(transfer_opt->transfer_id, *tx);

    FinalizationValidationInput val_input{.transfer = *transfer_opt,
                                          .file = *file_opt,
                                          .chunks = chunks,
                                          .expected_ciphertext_sha256 = request.expected_ciphertext_sha256};
    val_input.transfer.status = TransferStatus::Finalizing;
    val_input.file.status = FileStatus::Finalizing;

    const std::string effective_actor =
        request.caller_user_id.empty() ? file_opt->owner_user_id : request.caller_user_id;

    auto val_res = validate_finalization_preconditions(val_input);
    if (!val_res.is_valid) {
        release_db();
        const std::string fail_reason = (val_res.error_message.find("chunk") != std::string::npos ||
                                         val_res.error_message.find("Missing") != std::string::npos ||
                                         val_res.error_message.find("missing") != std::string::npos)
                                            ? "missing_chunks"
                                            : "precondition_failed";
        emit_finalization_failed(audit_publisher_, file_opt->file_id, effective_actor, transfer_opt->transfer_id,
                                 "WARNING", fail_reason, chunks.size(), transfer_opt->total_chunks);
        // Failure Rule: NEVER report AVAILABLE when finalization fails!
        throw FinalizationPreconditionException("Finalization precondition check failed: " + val_res.error_message);
    }

    // 9. Determine target version number
    auto latest_ver = version_repo_->find_active_version(file_opt->file_id, *tx);
    uint32_t target_version = latest_ver ? static_cast<uint32_t>(latest_ver->version_number + 1) : 1U;

    // 10. Assemble whole-object from staged chunks
    AssemblyResult assembly_res;
    try {
        assembly_res = assembly_engine_->assemble_version_object(file_opt->file_id, target_version,
                                                                 transfer_opt->transfer_id, chunks);
    } catch (const storage::S3IntegrityException&) {
        release_db();
        emit_finalization_failed(audit_publisher_, file_opt->file_id, effective_actor, transfer_opt->transfer_id,
                                 "SECURITY", "chunk_hash_tamper", chunks.size(), transfer_opt->total_chunks);
        throw;
    } catch (const std::exception&) {
        release_db();
        emit_finalization_failed(audit_publisher_, file_opt->file_id, effective_actor, transfer_opt->transfer_id,
                                 "WARNING", "s3_error", chunks.size(), transfer_opt->total_chunks);
        // Failure Rule: Leave staged chunks intact for retry/recovery
        throw;
    }

    // 11. Verify whole-ciphertext SHA-256 against client expectation (if provided)
    if (!request.expected_ciphertext_sha256.empty()) {
        std::string computed = assembly_res.computed_sha256;
        std::string expected = request.expected_ciphertext_sha256;
        bool match = (computed.size() == expected.size());
        if (match) {
            for (size_t i = 0; i < computed.size(); ++i) {
                if (std::tolower(static_cast<unsigned char>(computed[i])) !=
                    std::tolower(static_cast<unsigned char>(expected[i]))) {
                    match = false;
                    break;
                }
            }
        }
        if (!match) {
            release_db();
            emit_finalization_failed(audit_publisher_, file_opt->file_id, effective_actor, transfer_opt->transfer_id,
                                     "SECURITY", "chunk_hash_tamper", chunks.size(), transfer_opt->total_chunks);
            // Failure Rule: AVAILABLE must never be reported!
            throw ChunkIntegrityException("Whole-ciphertext SHA-256 integrity mismatch: expected " + expected +
                                          ", but computed " + computed);
        }
    }

    // 12. Atomic PostgreSQL commit
    auto now = std::chrono::system_clock::now();

    // a) Create immutable file_versions snapshot
    FileVersionEntity new_ver;
    new_ver.version_id = generate_uuid_v7();
    new_ver.file_id = file_opt->file_id;
    new_ver.version_number = static_cast<int32_t>(target_version);
    new_ver.encrypted_size = static_cast<int64_t>(assembly_res.total_bytes);
    new_ver.minio_object_key = assembly_res.target_object_key;
    new_ver.checksum_sha256 = assembly_res.computed_sha256;
    new_ver.is_active = true;
    new_ver.created_at = now;
    try {
        version_repo_->create_version(new_ver, *tx);

        // b) Transition file status to AVAILABLE
        file_repo_->update_status(file_opt->file_id, FileStatus::Finalizing, FileStatus::Available, *tx);

        // c) Transition transfer status to COMPLETED
        transfer_repo_->update_status(transfer_opt->transfer_id, TransferStatus::Completed, *tx);

        // d) Stage canonical E04 (file.upload.completed) outbox event
        if (audit_publisher_) {
            FilesAuditRecord record;
            record.event_type = "file.upload.completed";
            record.severity = "INFO";
            record.actor_type = effective_actor.empty() || effective_actor == "system" ? "SYSTEM" : "USER";
            record.actor_id = effective_actor.empty() ? "system" : effective_actor;
            record.target_type = "FILE";
            record.target_id = file_opt->file_id;
            record.correlation_id = resolve_finalization_correlation_id();
            record.metadata = {{"upload_id", transfer_opt->transfer_id},
                               {"version_number", std::to_string(target_version)},
                               {"total_bytes", std::to_string(assembly_res.total_bytes)},
                               {"chunk_count", std::to_string(chunks.size())},
                               {"checksum_sha256", assembly_res.computed_sha256}};
            audit_publisher_->publish_in_tx(record, *tx);
        }

        // Commit transaction!
        tx->commit();
        tx.reset();
        conn = db::PooledConnection{};
        if (audit_publisher_) {
            audit_publisher_->notify_relay();
        }
    } catch (const UniqueConstraintViolationException&) {
        release_db();
        // Concurrent finalization race: another concurrent request finalized this session
        auto retry_conn = pool_->acquire();
        auto& retry_default_conn = dynamic_cast<securecloud::files::db::DefaultDbConnection&>(*retry_conn);
        pqxx::work retry_tx(retry_default_conn.native_handle());

        auto active_ver = version_repo_->find_active_version(file_opt->file_id, retry_tx);
        if (active_ver) {
            retry_tx.commit();
            return FinalizeUploadResultDto{.file_id = file_opt->file_id,
                                           .version_number = active_ver->version_number,
                                           .total_bytes = static_cast<uint64_t>(active_ver->encrypted_size),
                                           .checksum_sha256 = active_ver->checksum_sha256,
                                           .available_at = active_ver->created_at,
                                           .is_idempotent_replay = true};
        }
        throw;
    }

    // 13. Staging chunks cleanup
    assembly_engine_->cleanup_staging_chunks(transfer_opt->transfer_id, chunks);

    return FinalizeUploadResultDto{.file_id = file_opt->file_id,
                                   .version_number = static_cast<int32_t>(target_version),
                                   .total_bytes = assembly_res.total_bytes,
                                   .checksum_sha256 = assembly_res.computed_sha256,
                                   .available_at = now,
                                   .is_idempotent_replay = false};
}

} // namespace securecloud::files::service
