#include "files/service/upload_session_manager.hpp"

#include "files/domain/metadata_validator.hpp"

#include <algorithm>
#include <iostream>
#include <set>

namespace securecloud::files::service {

UploadSessionManager::UploadSessionManager(std::shared_ptr<db::FilesDbConnectionPool> pool,
                                           std::shared_ptr<FileTransferRepository> transfer_repo,
                                           std::shared_ptr<FileChunkRepository> chunk_repo)
    : pool_(std::move(pool)), transfer_repo_(std::move(transfer_repo)), chunk_repo_(std::move(chunk_repo)) {
    if (!transfer_repo_ && pool_) {
        transfer_repo_ = std::make_shared<FileTransferRepository>(pool_);
    }
    if (!chunk_repo_ && pool_) {
        chunk_repo_ = std::make_shared<FileChunkRepository>(pool_);
    }
}

std::optional<UploadSession> UploadSessionManager::create_session(const v1::CreateFileUploadRequest& request) {
    std::lock_guard<std::mutex> lock(session_mutex_);

    std::string upload_id = generate_uuid_v7();
    auto now = std::chrono::system_clock::now();
    auto expires_at = now + std::chrono::hours(24);

    if (transfer_repo_) {
        try {
            FileTransferEntity transfer{
                .transfer_id = upload_id,
                .file_id = request.file_id(),
                .transfer_type = TransferType::Upload,
                .initiator_user_id = request.owner_user_id(),
                .initiator_device_id = request.owner_device_id(),
                .status = TransferStatus::Created,
                .total_chunks = static_cast<int32_t>(request.expected_chunk_count()),
                .accepted_chunks = 0,
                .total_bytes = static_cast<int64_t>(request.encrypted_size_bytes()),
                .transferred_bytes = 0,
                .created_at = now,
                .updated_at = now,
                .expires_at = expires_at,
            };
            if (pool_) {
                pqxx::work tx;
                transfer_repo_->create_transfer(transfer, tx);
                tx.commit();
            } else {
                // Autonomous or mock repository handling
            }
        } catch (const std::exception& ex) {
            std::cerr << "[SecureCloud] [files] Error persisting transfer session: " << ex.what() << "\n";
            return std::nullopt;
        }
    }

    UploadSession session{
        .upload_id = upload_id,
        .file_id = request.file_id(),
        .owner_user_id = request.owner_user_id(),
        .owner_device_id = request.owner_device_id(),
        .conversation_id = request.conversation_id(),
        .encrypted_size_bytes = request.encrypted_size_bytes(),
        .expected_chunk_count = request.expected_chunk_count(),
        .uploaded_chunk_count = 0,
        .encryption_version = request.encryption_version(),
        .status = v1::TRANSFER_STATUS_PENDING,
        .expires_at = expires_at,
    };

    in_memory_cache_[upload_id] = session;
    return session;
}

UploadSession UploadSessionManager::reconstruct_session_from_storage(const std::string& upload_id) {
    std::optional<FileTransferEntity> transfer_opt;

    if (transfer_repo_) {
        try {
            transfer_opt = transfer_repo_->find_by_id(upload_id);
        } catch (const std::exception& ex) {
            std::cerr << "[SecureCloud] [files] DB lookup failed during reconstruct: " << ex.what() << "\n";
        }
    }

    if (!transfer_opt) {
        auto it = in_memory_cache_.find(upload_id);
        if (it != in_memory_cache_.end()) {
            return it->second;
        }
        throw TransferNotFoundException("Transfer session not found: " + upload_id);
    }

    const auto& transfer = *transfer_opt;
    std::vector<int32_t> accepted_chunks;
    if (chunk_repo_) {
        try {
            accepted_chunks = chunk_repo_->get_accepted_chunk_indices(upload_id);
        } catch (const std::exception& ex) {
            std::cerr << "[SecureCloud] [files] Failed fetching chunks for " << upload_id << ": " << ex.what() << "\n";
        }
    }

    auto now = std::chrono::system_clock::now();
    v1::TransferStatus proto_status = v1::TRANSFER_STATUS_PENDING;

    switch (transfer.status) {
    case TransferStatus::Created:
        proto_status = v1::TRANSFER_STATUS_PENDING;
        break;
    case TransferStatus::Transferring:
        proto_status = v1::TRANSFER_STATUS_IN_PROGRESS;
        break;
    case TransferStatus::Finalizing:
        proto_status = v1::TRANSFER_STATUS_COMPLETED; // closest proto match
        break;
    case TransferStatus::Completed:
        proto_status = v1::TRANSFER_STATUS_COMPLETED;
        break;
    case TransferStatus::Expired:
        proto_status = v1::TRANSFER_STATUS_FAILED;
        break;
    case TransferStatus::Cancelled:
        proto_status = v1::TRANSFER_STATUS_CANCELLED;
        break;
    case TransferStatus::Failed:
        proto_status = v1::TRANSFER_STATUS_FAILED;
        break;
    }

    if (now > transfer.expires_at && transfer.status != TransferStatus::Cancelled &&
        transfer.status != TransferStatus::Completed) {
        proto_status = v1::TRANSFER_STATUS_FAILED;
    }

    UploadSession session{
        .upload_id = transfer.transfer_id,
        .file_id = transfer.file_id,
        .owner_user_id = transfer.initiator_user_id,
        .owner_device_id = transfer.initiator_device_id,
        .conversation_id = "",
        .encrypted_size_bytes = static_cast<uint64_t>(transfer.total_bytes),
        .expected_chunk_count = static_cast<uint32_t>(transfer.total_chunks),
        .uploaded_chunk_count = static_cast<uint32_t>(accepted_chunks.size()),
        .encryption_version = "",
        .status = proto_status,
        .expires_at = transfer.expires_at,
    };

    in_memory_cache_[upload_id] = session;
    return session;
}

std::optional<UploadSession> UploadSessionManager::get_session(const std::string& upload_id) {
    std::lock_guard<std::mutex> lock(session_mutex_);

    auto it = in_memory_cache_.find(upload_id);
    if (it != in_memory_cache_.end()) {
        auto now = std::chrono::system_clock::now();
        if (now > it->second.expires_at && it->second.status != v1::TRANSFER_STATUS_CANCELLED &&
            it->second.status != v1::TRANSFER_STATUS_COMPLETED) {
            it->second.status = v1::TRANSFER_STATUS_FAILED;
        }
        return it->second;
    }

    try {
        return reconstruct_session_from_storage(upload_id);
    } catch (const TransferNotFoundException&) {
        return std::nullopt;
    }
}

TransferProgress UploadSessionManager::get_transfer_progress(const std::string& upload_id) {
    std::lock_guard<std::mutex> lock(session_mutex_);

    std::optional<FileTransferEntity> transfer_opt;
    if (transfer_repo_) {
        try {
            transfer_opt = transfer_repo_->find_by_id(upload_id);
        } catch (const std::exception& ex) {
            std::cerr << "[SecureCloud] [files] DB lookup failed: " << ex.what() << "\n";
        }
    }

    auto now = std::chrono::system_clock::now();

    if (transfer_opt) {
        auto transfer = *transfer_opt;
        bool is_expired = (transfer.expires_at <= now);

        if (is_expired && transfer.status != TransferStatus::Cancelled &&
            transfer.status != TransferStatus::Completed) {
            transfer.status = TransferStatus::Expired;
            if (transfer_repo_) {
                try {
                    transfer_repo_->update_status(upload_id, TransferStatus::Expired);
                } catch (...) {
                }
            }
        }

        std::vector<int32_t> accepted;
        if (chunk_repo_) {
            try {
                accepted = chunk_repo_->get_accepted_chunk_indices(upload_id);
            } catch (const std::exception& ex) {
                std::cerr << "[SecureCloud] [files] Failed fetching chunks: " << ex.what() << "\n";
            }
        }
        std::sort(accepted.begin(), accepted.end());

        std::set<int32_t> accepted_set(accepted.begin(), accepted.end());
        std::vector<int32_t> missing;
        for (int32_t i = 0; i < transfer.total_chunks; ++i) {
            if (accepted_set.find(i) == accepted_set.end()) {
                missing.push_back(i);
            }
        }

        bool is_complete = (transfer.total_chunks > 0 && accepted.size() == static_cast<size_t>(transfer.total_chunks));

        return TransferProgress{
            .transfer_id = transfer.transfer_id,
            .file_id = transfer.file_id,
            .status = transfer.status,
            .total_chunks = static_cast<uint32_t>(transfer.total_chunks),
            .accepted_chunks = static_cast<uint32_t>(accepted.size()),
            .transferred_bytes = transfer.transferred_bytes,
            .total_bytes = transfer.total_bytes,
            .accepted_chunk_indices = accepted,
            .missing_chunk_indices = missing,
            .expires_at = transfer.expires_at,
            .is_expired = is_expired,
            .is_complete = is_complete,
        };
    }

    // Check in-memory cache as fallback
    auto it = in_memory_cache_.find(upload_id);
    if (it != in_memory_cache_.end()) {
        const auto& s = it->second;
        bool is_expired = (s.expires_at <= now);
        TransferStatus status = TransferStatus::Created;
        if (s.status == v1::TRANSFER_STATUS_CANCELLED) {
            status = TransferStatus::Cancelled;
        } else if (is_expired) {
            status = TransferStatus::Expired;
        } else if (s.uploaded_chunk_count == s.expected_chunk_count && s.expected_chunk_count > 0) {
            status = TransferStatus::Completed;
        } else if (s.uploaded_chunk_count > 0) {
            status = TransferStatus::Transferring;
        }

        std::vector<int32_t> accepted;
        for (uint32_t i = 0; i < s.uploaded_chunk_count; ++i) {
            accepted.push_back(static_cast<int32_t>(i));
        }
        std::vector<int32_t> missing;
        for (uint32_t i = s.uploaded_chunk_count; i < s.expected_chunk_count; ++i) {
            missing.push_back(static_cast<int32_t>(i));
        }

        return TransferProgress{
            .transfer_id = s.upload_id,
            .file_id = s.file_id,
            .status = status,
            .total_chunks = s.expected_chunk_count,
            .accepted_chunks = s.uploaded_chunk_count,
            .transferred_bytes = 0,
            .total_bytes = static_cast<int64_t>(s.encrypted_size_bytes),
            .accepted_chunk_indices = accepted,
            .missing_chunk_indices = missing,
            .expires_at = s.expires_at,
            .is_expired = is_expired,
            .is_complete = (s.uploaded_chunk_count == s.expected_chunk_count && s.expected_chunk_count > 0),
        };
    }

    throw TransferNotFoundException("Transfer session not found: " + upload_id);
}

std::vector<int32_t> UploadSessionManager::get_missing_chunk_indices(const std::string& upload_id) {
    return get_transfer_progress(upload_id).missing_chunk_indices;
}

bool UploadSessionManager::cancel_session(const std::string& upload_id, const std::string& /*reason*/) {
    std::lock_guard<std::mutex> lock(session_mutex_);

    bool found = false;
    if (transfer_repo_) {
        try {
            auto transfer_opt = transfer_repo_->find_by_id(upload_id);
            if (transfer_opt) {
                transfer_repo_->update_status(upload_id, TransferStatus::Cancelled);
                found = true;
            }
        } catch (const std::exception& ex) {
            std::cerr << "[SecureCloud] [files] Failed to cancel transfer in DB: " << ex.what() << "\n";
        }
    }

    auto it = in_memory_cache_.find(upload_id);
    if (it != in_memory_cache_.end()) {
        it->second.status = v1::TRANSFER_STATUS_CANCELLED;
        found = true;
    }

    return found;
}

bool UploadSessionManager::record_chunk_upload(const std::string& upload_id, uint32_t /*chunk_index*/,
                                               const std::string& /*ciphertext_sha256*/) {
    std::lock_guard<std::mutex> lock(session_mutex_);
    auto it = in_memory_cache_.find(upload_id);
    if (it != in_memory_cache_.end()) {
        it->second.uploaded_chunk_count++;
        it->second.status = v1::TRANSFER_STATUS_IN_PROGRESS;
        return true;
    }
    return false;
}

bool UploadSessionManager::finalize_session(const std::string& upload_id, const std::string& /*expected_sha256*/) {
    std::lock_guard<std::mutex> lock(session_mutex_);
    auto it = in_memory_cache_.find(upload_id);
    if (it != in_memory_cache_.end()) {
        it->second.status = v1::TRANSFER_STATUS_COMPLETED;
        return true;
    }
    return false;
}

} // namespace securecloud::files::service
