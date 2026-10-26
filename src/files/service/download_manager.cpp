#include "files/service/download_manager.hpp"

#include <stdexcept>

namespace securecloud::files::service {

DownloadManager::DownloadManager(
    std::shared_ptr<db::FilesDbConnectionPool> pool,
    std::shared_ptr<ChunkDownloadEngine> download_engine,
    std::shared_ptr<FileRepository> file_repo,
    std::shared_ptr<FileVersionRepository> version_repo,
    std::shared_ptr<FileAccessRepository> access_repo)
    : pool_(std::move(pool)),
      download_engine_(std::move(download_engine)),
      file_repo_(std::move(file_repo)),
      version_repo_(std::move(version_repo)),
      access_repo_(std::move(access_repo)) {
    if (!file_repo_ && pool_) {
        file_repo_ = std::make_shared<FileRepository>(pool_);
    }
    if (!version_repo_ && pool_) {
        version_repo_ = std::make_shared<FileVersionRepository>(pool_);
    }
    if (!access_repo_ && pool_) {
        access_repo_ = std::make_shared<FileAccessRepository>(pool_);
    }
}

bool DownloadManager::authorize_download(const std::string& file_id, const std::string& caller_user_id) {
    if (caller_user_id.empty() || !pool_) {
        return false;
    }

    try {
        auto conn = pool_->acquire_connection();
        pqxx::work tx(*conn);

        auto file_opt = file_repo_->find_by_id(file_id, tx);
        if (!file_opt) {
            return false;
        }

        if (file_opt->owner_user_id == caller_user_id) {
            return true;
        }

        return access_repo_->check_access(file_id, caller_user_id, FilePermission::Read, tx);
    } catch (...) {
        return false;
    }
}

DownloadChunkResult DownloadManager::get_chunk_versioned(
    const std::string& file_id,
    int32_t version_number,
    uint32_t chunk_index,
    const std::string& caller_user_id) {
    if (!pool_) {
        throw std::runtime_error("Database connection pool is uninitialized in DownloadManager");
    }
    if (!download_engine_) {
        throw std::runtime_error("ChunkDownloadEngine is uninitialized in DownloadManager");
    }

    auto conn = pool_->acquire_connection();
    pqxx::work tx(*conn);

    // 1. Fetch file record
    auto file_opt = file_repo_->find_by_id(file_id, tx);
    if (!file_opt) {
        throw FileNotFoundException("File not found: " + file_id);
    }

    // 2. Authorization check
    bool is_owner = (!caller_user_id.empty() && file_opt->owner_user_id == caller_user_id);
    bool has_read_perm = false;
    if (!is_owner && !caller_user_id.empty()) {
        has_read_perm = access_repo_->check_access(file_id, caller_user_id, FilePermission::Read, tx);
    }
    if (!is_owner && !has_read_perm && !caller_user_id.empty()) {
        throw UnauthorizedFileAccessException(
            "Caller '" + caller_user_id + "' lacks READ access to file: " + file_id);
    }

    // 3. Version snapshot lookup
    std::optional<FileVersionEntity> version_opt;
    if (version_number > 0) {
        auto versions = version_repo_->list_versions(file_id, tx);
        for (const auto& v : versions) {
            if (v.version_number == version_number) {
                version_opt = v;
                break;
            }
        }
    } else {
        version_opt = version_repo_->find_active_version(file_id, tx);
    }

    if (!version_opt) {
        throw EntityNotFoundException("Version snapshot not found for file: " + file_id);
    }

    // 4. Precondition validation
    DownloadValidationInput val_input{
        .file_id = file_id,
        .requested_version = version_number,
        .chunk_index = chunk_index,
        .file = *file_opt,
        .version = version_opt,
        .caller_user_id = caller_user_id,
        .has_read_permission = (is_owner || has_read_perm || caller_user_id.empty())
    };

    auto val_res = validate_download_preconditions(val_input);
    if (!val_res.is_valid) {
        throw InvalidDownloadPreconditionException(val_res.error_message);
    }

    // 5. Fetch chunk from storage engine
    auto chunk_res = download_engine_->fetch_chunk(
        file_id, version_opt->version_number, chunk_index,
        static_cast<uint64_t>(version_opt->encrypted_size));

    return DownloadChunkResult{
        .file_id = file_id,
        .version_number = chunk_res.version_number,
        .chunk_index = chunk_res.chunk_index,
        .encrypted_data = std::move(chunk_res.encrypted_data),
        .chunk_size_bytes = chunk_res.chunk_size_bytes,
        .ciphertext_sha256 = std::move(chunk_res.ciphertext_sha256)
    };
}

std::optional<DownloadChunkResult> DownloadManager::get_chunk(const std::string& file_id, uint32_t chunk_index) {
    try {
        return get_chunk_versioned(file_id, 0, chunk_index, "");
    } catch (...) {
        return std::nullopt;
    }
}

DownloadResumeModel DownloadManager::prepare_resume_session(
    const std::string& file_id,
    int32_t version_number,
    uint32_t starting_chunk,
    const std::string& caller_user_id) {
    if (!pool_) {
        throw std::runtime_error("Database connection pool is uninitialized in DownloadManager");
    }

    auto conn = pool_->acquire_connection();
    pqxx::work tx(*conn);

    auto file_opt = file_repo_->find_by_id(file_id, tx);
    if (!file_opt) {
        throw FileNotFoundException("File not found: " + file_id);
    }

    bool is_owner = (!caller_user_id.empty() && file_opt->owner_user_id == caller_user_id);
    bool has_read_perm = false;
    if (!is_owner && !caller_user_id.empty()) {
        has_read_perm = access_repo_->check_access(file_id, caller_user_id, FilePermission::Read, tx);
    }
    if (!is_owner && !has_read_perm && !caller_user_id.empty()) {
        throw UnauthorizedFileAccessException(
            "Caller '" + caller_user_id + "' lacks READ access to file: " + file_id);
    }

    if (file_opt->status != FileStatus::Available) {
        throw InvalidDownloadPreconditionException(
            "File is not available for download; current status: " +
            std::string(to_string(file_opt->status)));
    }

    std::optional<FileVersionEntity> version_opt;
    if (version_number > 0) {
        auto versions = version_repo_->list_versions(file_id, tx);
        for (const auto& v : versions) {
            if (v.version_number == version_number) {
                version_opt = v;
                break;
            }
        }
    } else {
        version_opt = version_repo_->find_active_version(file_id, tx);
    }

    if (!version_opt) {
        throw EntityNotFoundException("Version snapshot not found for file: " + file_id);
    }

    uint64_t total_bytes = static_cast<uint64_t>(version_opt->encrypted_size);
    uint32_t total_chunks = (total_bytes == 0)
                                ? 0
                                : static_cast<uint32_t>((total_bytes + k_standard_chunk_size - 1) / k_standard_chunk_size);

    if (starting_chunk > 0 && starting_chunk >= total_chunks) {
        throw std::out_of_range(
            "Starting chunk " + std::to_string(starting_chunk) +
            " is out of bounds for file " + file_id + " (total chunks: " +
            std::to_string(total_chunks) + ")");
    }

    return DownloadResumeModel{
        .file_id = file_id,
        .version_number = version_opt->version_number,
        .starting_chunk = starting_chunk,
        .total_chunks = total_chunks,
        .total_bytes = total_bytes,
        .ciphertext_sha256 = version_opt->checksum_sha256
    };
}

} // namespace securecloud::files::service
