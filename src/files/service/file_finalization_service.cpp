#include "files/service/file_finalization_service.hpp"

#include "files/domain/metadata_validator.hpp"

#include <iostream>

namespace securecloud::files::service {

FileFinalizationService::FileFinalizationService(std::shared_ptr<db::FilesDbConnectionPool> pool,
                                                 std::shared_ptr<ObjectAssemblyEngine> assembly_engine,
                                                 std::shared_ptr<FileTransferRepository> transfer_repo,
                                                 std::shared_ptr<FileRepository> file_repo,
                                                 std::shared_ptr<FileVersionRepository> version_repo,
                                                 std::shared_ptr<FileChunkRepository> chunk_repo,
                                                 std::shared_ptr<FilesOutboxRepository> outbox_repo)
    : pool_(std::move(pool)), assembly_engine_(std::move(assembly_engine)), transfer_repo_(std::move(transfer_repo)),
      file_repo_(std::move(file_repo)), version_repo_(std::move(version_repo)), chunk_repo_(std::move(chunk_repo)),
      outbox_repo_(std::move(outbox_repo)) {
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

    pqxx::work tx;

    // 1. Fetch transfer session
    auto transfer_opt = transfer_repo_->find_by_id(request.upload_id, tx);
    if (!transfer_opt) {
        tx.abort();
        throw EntityNotFoundException("Transfer session not found: " + request.upload_id);
    }

    // 2. Validate file_id association if specified in request
    if (!request.file_id.empty() && request.file_id != transfer_opt->file_id) {
        tx.abort();
        throw FinalizationPreconditionException("Request file_id (" + request.file_id +
                                                ") does not match transfer session file_id (" + transfer_opt->file_id +
                                                ")");
    }

    // 3. Fetch file entity
    auto file_opt = file_repo_->find_by_id(transfer_opt->file_id, tx);
    if (!file_opt) {
        tx.abort();
        throw EntityNotFoundException("File record not found: " + transfer_opt->file_id);
    }

    // 4. Verify caller authorization
    if (!request.caller_user_id.empty() && file_opt->owner_user_id != request.caller_user_id) {
        tx.abort();
        throw FinalizationPreconditionException("Caller user ID does not match file owner ID");
    }

    // 5. Anti-split-brain Idempotency Check: if transfer is already completed
    if (transfer_opt->status == TransferStatus::Completed) {
        auto active_ver = version_repo_->find_active_version(file_opt->file_id, tx);
        if (active_ver) {
            tx.commit();
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
        tx.abort();
        throw FinalizationPreconditionException("Cannot finalize a cancelled transfer session");
    }
    if (transfer_opt->status == TransferStatus::Expired) {
        tx.abort();
        throw FinalizationPreconditionException("Cannot finalize an expired transfer session");
    }
    if (transfer_opt->status == TransferStatus::Failed) {
        tx.abort();
        throw FinalizationPreconditionException("Cannot finalize a failed transfer session");
    }

    // 7. Transition states to FINALIZING
    transfer_repo_->update_status(transfer_opt->transfer_id, TransferStatus::Finalizing, tx);
    file_repo_->update_status(file_opt->file_id, file_opt->status, FileStatus::Finalizing, tx);

    // 8. Load chunks and perform authoritative precondition validation
    auto chunks = chunk_repo_->list_chunks_for_transfer(transfer_opt->transfer_id, tx);

    FinalizationValidationInput val_input{.transfer = *transfer_opt,
                                          .file = *file_opt,
                                          .chunks = chunks,
                                          .expected_ciphertext_sha256 = request.expected_ciphertext_sha256};
    val_input.transfer.status = TransferStatus::Finalizing;
    val_input.file.status = FileStatus::Finalizing;

    auto val_res = validate_finalization_preconditions(val_input);
    if (!val_res.is_valid) {
        tx.abort();
        // Failure Rule: NEVER report AVAILABLE when finalization fails!
        throw FinalizationPreconditionException("Finalization precondition check failed: " + val_res.error_message);
    }

    // 9. Determine target version number
    auto latest_ver = version_repo_->find_active_version(file_opt->file_id, tx);
    uint32_t target_version = latest_ver ? static_cast<uint32_t>(latest_ver->version_number + 1) : 1U;

    // 10. Assemble whole-object from staged chunks
    AssemblyResult assembly_res;
    try {
        assembly_res = assembly_engine_->assemble_version_object(file_opt->file_id, target_version,
                                                                 transfer_opt->transfer_id, chunks);
    } catch (const std::exception& e) {
        tx.abort();
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
            tx.abort();
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
        version_repo_->create_version(new_ver, tx);

        // b) Transition file status to AVAILABLE
        file_repo_->update_status(file_opt->file_id, FileStatus::Finalizing, FileStatus::Available, tx);

        // c) Transition transfer status to COMPLETED
        transfer_repo_->update_status(transfer_opt->transfer_id, TransferStatus::Completed, tx);

        // d) Stage outbox event for FILE_AVAILABLE
        FilesOutboxEntity outbox;
        outbox.event_id = generate_uuid_v7();
        outbox.event_type = "FILE_AVAILABLE";
        outbox.aggregate_id = file_opt->file_id;
        outbox.payload_json = "{\"file_id\":\"" + file_opt->file_id +
                              "\",\"version_number\":" + std::to_string(target_version) + ",\"owner_user_id\":\"" +
                              file_opt->owner_user_id + "\",\"checksum_sha256\":\"" + assembly_res.computed_sha256 +
                              "\",\"total_bytes\":" + std::to_string(assembly_res.total_bytes) + "}";
        outbox.created_at = now;
        outbox_repo_->stage_event(outbox, tx);

        // Commit transaction!
        tx.commit();
    } catch (const UniqueConstraintViolationException&) {
        tx.abort();
        // Concurrent finalization race: another concurrent request finalized this session
        pqxx::work retry_tx;
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
