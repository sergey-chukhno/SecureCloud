#include "files/service/chunk_storage_service.hpp"

#include "files/domain/metadata_validator.hpp"

#include <algorithm>
#include <cctype>
#include <iostream>

namespace securecloud::files::service {

namespace {

bool hashes_equal(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    return std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
        return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
    });
}

} // namespace

ChunkStorageService::ChunkStorageService(std::shared_ptr<db::FilesDbConnectionPool> pool,
                                         std::shared_ptr<storage::S3Client> s3_client,
                                         std::shared_ptr<FileTransferRepository> transfer_repo,
                                         std::shared_ptr<FileChunkRepository> chunk_repo,
                                         std::shared_ptr<FileRepository> file_repo)
    : pool_(std::move(pool)), s3_client_(std::move(s3_client)), transfer_repo_(std::move(transfer_repo)),
      chunk_repo_(std::move(chunk_repo)), file_repo_(std::move(file_repo)) {
    if (!transfer_repo_ && pool_) {
        transfer_repo_ = std::make_shared<FileTransferRepository>(pool_);
    }
    if (!chunk_repo_ && pool_) {
        chunk_repo_ = std::make_shared<FileChunkRepository>(pool_);
    }
    if (!file_repo_ && pool_) {
        file_repo_ = std::make_shared<FileRepository>(pool_);
    }
}

std::string ChunkStorageService::build_staging_key(const std::string& upload_id, uint32_t chunk_index) {
    return "staging/" + upload_id + "/" + std::to_string(chunk_index);
}

ChunkStoreResult ChunkStorageService::store_chunk(const ChunkPayloadDto& chunk_dto, const std::string& caller_user_id) {
    std::string staging_key = build_staging_key(chunk_dto.upload_id, chunk_dto.chunk_index);
    auto now = std::chrono::system_clock::now();

    if (pool_) {
        pqxx::work tx;

        auto transfer_opt = transfer_repo_->find_by_id(chunk_dto.upload_id, tx);
        if (!transfer_opt) {
            tx.abort();
            throw TransferNotFoundException("Upload transfer session not found: " + chunk_dto.upload_id);
        }

        const auto& transfer = *transfer_opt;

        // Verify caller ownership
        if (!caller_user_id.empty() && caller_user_id != "gateway" && caller_user_id != "DNS:gateway" &&
            transfer.initiator_user_id != caller_user_id) {
            tx.abort();
            throw UnauthorizedTransferException("Caller '" + caller_user_id + "' is not the initiator of transfer " +
                                                chunk_dto.upload_id);
        }

        // Verify transfer status
        if (transfer.status == TransferStatus::Cancelled) {
            tx.abort();
            throw TransferCancelledException("Upload transfer session is cancelled: " + chunk_dto.upload_id);
        }
        if (transfer.status == TransferStatus::Expired) {
            tx.abort();
            throw TransferExpiredException("Upload transfer session is expired: " + chunk_dto.upload_id);
        }
        if (transfer.status == TransferStatus::Completed) {
            tx.abort();
            throw TransferException("Upload transfer session is already completed: " + chunk_dto.upload_id);
        }

        // Check lease expiration
        if (now > transfer.expires_at) {
            transfer_repo_->update_status(chunk_dto.upload_id, TransferStatus::Expired, tx);
            tx.commit();
            throw TransferExpiredException("Upload transfer session lease expired: " + chunk_dto.upload_id);
        }

        // Check if chunk is already present (Idempotency pre-check)
        auto existing_chunks = chunk_repo_->list_chunks_for_transfer(chunk_dto.upload_id, tx);
        for (const auto& ec : existing_chunks) {
            if (ec.chunk_index == static_cast<int32_t>(chunk_dto.chunk_index)) {
                if (hashes_equal(ec.chunk_hash_sha256, chunk_dto.claimed_sha256)) {
                    // Safe idempotent replay! No MinIO re-upload, no DB counter mutation
                    tx.commit();
                    return ChunkStoreResult{
                        .accepted = true,
                        .is_duplicate = true,
                        .received_sha256 = chunk_dto.claimed_sha256,
                        .chunk_index = chunk_dto.chunk_index,
                        .bytes_written = static_cast<int64_t>(chunk_dto.chunk_size_bytes),
                    };
                } else {
                    tx.abort();
                    throw ChunkIntegrityException("Conflicting chunk content for index " +
                                                  std::to_string(chunk_dto.chunk_index) +
                                                  ": existing hash differs from submitted hash");
                }
            }
        }

        // Stage payload in MinIO
        if (s3_client_) {
            s3_client_->put_object(staging_key, chunk_dto.encrypted_data, "application/octet-stream",
                                   chunk_dto.claimed_sha256);
        }

        // Prepare chunk entity
        FileChunkEntity chunk_entity{
            .chunk_id = generate_uuid_v7(),
            .transfer_id = chunk_dto.upload_id,
            .chunk_index = static_cast<int32_t>(chunk_dto.chunk_index),
            .byte_offset = static_cast<int64_t>(chunk_dto.chunk_index) * k_standard_chunk_size,
            .chunk_size = static_cast<int32_t>(chunk_dto.chunk_size_bytes),
            .chunk_hash_sha256 = chunk_dto.claimed_sha256,
            .minio_chunk_key = staging_key,
            .status = ChunkStatus::Received,
            .created_at = now,
        };

        auto record_result = chunk_repo_->record_chunk(chunk_entity, tx);
        if (record_result == ChunkRecordResult::ConflictHashMismatch) {
            tx.abort();
            throw ChunkIntegrityException("Conflicting chunk content for index " +
                                          std::to_string(chunk_dto.chunk_index));
        }
        if (record_result == ChunkRecordResult::AlreadyExistsIdentical) {
            tx.commit();
            return ChunkStoreResult{
                .accepted = true,
                .is_duplicate = true,
                .received_sha256 = chunk_dto.claimed_sha256,
                .chunk_index = chunk_dto.chunk_index,
                .bytes_written = static_cast<int64_t>(chunk_dto.chunk_size_bytes),
            };
        }

        // If first chunk received, transition status Created -> Transferring
        if (transfer.status == TransferStatus::Created) {
            transfer_repo_->update_status(chunk_dto.upload_id, TransferStatus::Transferring, tx);
            if (file_repo_) {
                file_repo_->update_status(transfer.file_id, FileStatus::Created, FileStatus::Uploading, tx);
            }
        }

        transfer_repo_->increment_chunk_progress(chunk_dto.upload_id, chunk_dto.chunk_size_bytes, tx);

        int32_t accepted_count = chunk_repo_->count_accepted_chunks(chunk_dto.upload_id, tx);
        if (transfer.total_chunks > 0 && accepted_count >= transfer.total_chunks) {
            transfer_repo_->update_status(chunk_dto.upload_id, TransferStatus::Finalizing, tx);
        }

        tx.commit();
        return ChunkStoreResult{
            .accepted = true,
            .is_duplicate = false,
            .received_sha256 = chunk_dto.claimed_sha256,
            .chunk_index = chunk_dto.chunk_index,
            .bytes_written = static_cast<int64_t>(chunk_dto.chunk_size_bytes),
        };
    }

    // Fallback path without database connection pool (for unit tests / mock setups)
    if (transfer_repo_) {
        auto transfer_opt = transfer_repo_->find_by_id(chunk_dto.upload_id);
        if (!transfer_opt) {
            throw TransferNotFoundException("Upload transfer session not found: " + chunk_dto.upload_id);
        }

        const auto& transfer = *transfer_opt;
        if (!caller_user_id.empty() && caller_user_id != "gateway" && caller_user_id != "DNS:gateway" &&
            transfer.initiator_user_id != caller_user_id) {
            throw UnauthorizedTransferException("Caller '" + caller_user_id + "' is not the initiator of transfer " +
                                                chunk_dto.upload_id);
        }
        if (transfer.status == TransferStatus::Cancelled) {
            throw TransferCancelledException("Upload transfer session is cancelled: " + chunk_dto.upload_id);
        }
        if (transfer.status == TransferStatus::Expired) {
            throw TransferExpiredException("Upload transfer session is expired: " + chunk_dto.upload_id);
        }
        if (transfer.status == TransferStatus::Completed) {
            throw TransferException("Upload transfer session is already completed: " + chunk_dto.upload_id);
        }
        if (now > transfer.expires_at) {
            transfer_repo_->update_status(chunk_dto.upload_id, TransferStatus::Expired);
            throw TransferExpiredException("Upload transfer session lease expired: " + chunk_dto.upload_id);
        }

        if (chunk_repo_) {
            auto existing_chunks = chunk_repo_->list_chunks_for_transfer(chunk_dto.upload_id);
            for (const auto& ec : existing_chunks) {
                if (ec.chunk_index == static_cast<int32_t>(chunk_dto.chunk_index)) {
                    if (hashes_equal(ec.chunk_hash_sha256, chunk_dto.claimed_sha256)) {
                        return ChunkStoreResult{
                            .accepted = true,
                            .is_duplicate = true,
                            .received_sha256 = chunk_dto.claimed_sha256,
                            .chunk_index = chunk_dto.chunk_index,
                            .bytes_written = static_cast<int64_t>(chunk_dto.chunk_size_bytes),
                        };
                    } else {
                        throw ChunkIntegrityException("Conflicting chunk content for index " +
                                                      std::to_string(chunk_dto.chunk_index));
                    }
                }
            }
        }

        if (s3_client_) {
            s3_client_->put_object(staging_key, chunk_dto.encrypted_data, "application/octet-stream",
                                   chunk_dto.claimed_sha256);
        }

        if (transfer.status == TransferStatus::Created) {
            transfer_repo_->update_status(chunk_dto.upload_id, TransferStatus::Transferring);
            if (file_repo_) {
                file_repo_->update_status(transfer.file_id, FileStatus::Created, FileStatus::Uploading);
            }
        }

        transfer_repo_->increment_chunk_progress(chunk_dto.upload_id, chunk_dto.chunk_size_bytes);

        if (chunk_repo_) {
            int32_t accepted_count = chunk_repo_->count_accepted_chunks(chunk_dto.upload_id);
            if (transfer.total_chunks > 0 && accepted_count >= transfer.total_chunks) {
                transfer_repo_->update_status(chunk_dto.upload_id, TransferStatus::Finalizing);
            }
        }
    } else {
        // Pure S3 mode without DB repository
        if (s3_client_) {
            s3_client_->put_object(staging_key, chunk_dto.encrypted_data, "application/octet-stream",
                                   chunk_dto.claimed_sha256);
        }
    }

    return ChunkStoreResult{
        .accepted = true,
        .is_duplicate = false,
        .received_sha256 = chunk_dto.claimed_sha256,
        .chunk_index = chunk_dto.chunk_index,
        .bytes_written = static_cast<int64_t>(chunk_dto.chunk_size_bytes),
    };
}

} // namespace securecloud::files::service
