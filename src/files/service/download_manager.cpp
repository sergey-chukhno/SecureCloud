#include "files/service/download_manager.hpp"

#include "files/db/files_connection_pool.hpp"
#include "files/domain/metadata_validator.hpp"
#include "files/repository/files_outbox_repository.hpp"
#include "files/service/files_caller_context.hpp"

#include <stdexcept>

namespace securecloud::files::service {

namespace {

[[nodiscard]] std::string resolve_download_correlation_id() {
    if (const auto ctx = current_files_caller_context(); ctx && !ctx->correlation_id.empty()) {
        return ctx->correlation_id;
    }
    return generate_uuid_v7();
}

[[nodiscard]] std::string resolve_download_device_id() {
    if (const auto ctx = current_files_caller_context(); ctx && !ctx->device_id.empty()) {
        return ctx->device_id;
    }
    return "unknown";
}

[[nodiscard]] std::string resolve_download_actor_type(std::string_view actor_id) noexcept {
    if (actor_id.empty() || actor_id == "system") {
        return "SYSTEM";
    }
    if (actor_id == "gateway" || actor_id == "authenticated_peer") {
        return "SERVICE";
    }
    return "USER";
}

void emit_download_initiated(const std::shared_ptr<FilesAuditEventPublisher>& publisher, const std::string& file_id,
                             const std::string& caller_user_id, int32_t version_number, uint32_t starting_chunk,
                             uint32_t total_chunks) noexcept {
    if (!publisher) {
        return;
    }
    const std::string effective_actor = caller_user_id.empty() ? "system" : caller_user_id;
    FilesAuditRecord record;
    record.event_type = "file.download.initiated";
    record.severity = "INFO";
    record.actor_type = resolve_download_actor_type(effective_actor);
    record.actor_id = effective_actor;
    record.target_type = file_id.empty() ? "SERVICE" : "FILE";
    record.target_id = file_id.empty() ? "files" : file_id;
    record.correlation_id = resolve_download_correlation_id();
    record.metadata = {{"version_number", std::to_string(version_number)},
                       {"starting_chunk", std::to_string(starting_chunk)},
                       {"total_chunks", std::to_string(total_chunks)},
                       {"device_id", resolve_download_device_id()}};
    publisher->publish_autonomous(record);
}

void emit_download_denied(const std::shared_ptr<FilesAuditEventPublisher>& publisher, const std::string& file_id,
                          const std::string& caller_user_id, std::string_view operation) noexcept {
    if (!publisher || current_files_caller_context().has_value()) {
        return;
    }
    const std::string effective_actor = caller_user_id.empty() ? "unknown" : caller_user_id;
    FilesAuditRecord record;
    record.event_type = "file.access.denied";
    record.severity = "SECURITY";
    record.actor_type = resolve_download_actor_type(effective_actor);
    record.actor_id = effective_actor;
    record.target_type = file_id.empty() ? "SERVICE" : "FILE";
    record.target_id = file_id.empty() ? "files" : file_id;
    record.correlation_id = resolve_download_correlation_id();
    record.metadata = {{"operation", std::string(operation)},
                       {"reason", "unauthorized_read"},
                       {"device_id", resolve_download_device_id()}};
    publisher->publish_autonomous(record);
}

} // namespace

DownloadManager::DownloadManager(std::shared_ptr<db::FilesDbConnectionPool> pool,
                                 std::shared_ptr<ChunkDownloadEngine> download_engine,
                                 std::shared_ptr<FileRepository> file_repo,
                                 std::shared_ptr<FileVersionRepository> version_repo,
                                 std::shared_ptr<FileAccessRepository> access_repo,
                                 std::shared_ptr<FilesAuditEventPublisher> audit_publisher)
    : pool_(std::move(pool)), download_engine_(std::move(download_engine)), file_repo_(std::move(file_repo)),
      version_repo_(std::move(version_repo)), access_repo_(std::move(access_repo)),
      audit_publisher_(std::move(audit_publisher)) {
    if (!file_repo_ && pool_) {
        file_repo_ = std::make_shared<FileRepository>(pool_);
    }
    if (!version_repo_ && pool_) {
        version_repo_ = std::make_shared<FileVersionRepository>(pool_);
    }
    if (!access_repo_ && pool_) {
        access_repo_ = std::make_shared<FileAccessRepository>(pool_);
    }
    if (!audit_publisher_ && pool_) {
        audit_publisher_ = std::make_shared<FilesAuditEventPublisher>(std::make_shared<FilesOutboxRepository>(pool_));
    }
}

bool DownloadManager::authorize_download(const std::string& file_id, const std::string& caller_user_id) {
    if (caller_user_id.empty() || !pool_) {
        return false;
    }

    if (caller_user_id == "system" || caller_user_id == "authenticated_peer" || caller_user_id == "gateway") {
        return true;
    }

    try {
        auto conn = pool_->acquire();

        auto& default_conn = dynamic_cast<securecloud::files::db::DefaultDbConnection&>(*conn);
        pqxx::work tx(default_conn.native_handle());

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

DownloadChunkResult DownloadManager::get_chunk_versioned(const std::string& file_id, int32_t version_number,
                                                         uint32_t chunk_index, const std::string& caller_user_id) {
    if (!pool_) {
        throw std::runtime_error("Database connection pool is uninitialized in DownloadManager");
    }
    if (!download_engine_) {
        throw std::runtime_error("ChunkDownloadEngine is uninitialized in DownloadManager");
    }

    std::optional<FileEntity> file_opt;
    std::optional<FileVersionEntity> version_opt;
    bool is_owner = false;
    bool has_read_perm = false;
    bool unauthorized = false;
    {
        auto conn = pool_->acquire();
        auto& default_conn = dynamic_cast<securecloud::files::db::DefaultDbConnection&>(*conn);
        pqxx::work tx(default_conn.native_handle());

        // 1. Fetch file record
        file_opt = file_repo_->find_by_id(file_id, tx);
        if (!file_opt) {
            throw FileNotFoundException("File not found: " + file_id);
        }

        // 2. Authorization check
        bool is_trusted_peer = (caller_user_id.empty() || caller_user_id == "system" ||
                                caller_user_id == "authenticated_peer" || caller_user_id == "gateway");
        is_owner = (!caller_user_id.empty() && file_opt->owner_user_id == caller_user_id);
        has_read_perm = is_trusted_peer;
        if (!is_owner && !is_trusted_peer && !caller_user_id.empty()) {
            has_read_perm = access_repo_->check_access(file_id, caller_user_id, FilePermission::Read, tx);
        }
        if (!is_owner && !has_read_perm) {
            tx.abort();
            unauthorized = true;
        } else {
            // 3. Lifecycle state check (must be AVAILABLE)
            if (file_opt->status != FileStatus::Available) {
                throw InvalidDownloadPreconditionException("File is not available for download; current status: " +
                                                           std::string(to_string(file_opt->status)));
            }

            // 4. Version snapshot lookup
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
        }
    }

    if (unauthorized) {
        emit_download_denied(audit_publisher_, file_id, caller_user_id, "DownloadChunk");
        throw UnauthorizedFileAccessException("Caller '" + caller_user_id + "' lacks READ access to file: " + file_id);
    }

    // 5. Precondition validation
    DownloadValidationInput val_input{.file_id = file_id,
                                      .requested_version = version_number,
                                      .chunk_index = chunk_index,
                                      .file = *file_opt,
                                      .version = version_opt,
                                      .caller_user_id = caller_user_id,
                                      .has_read_permission = (is_owner || has_read_perm)};

    auto val_res = validate_download_preconditions(val_input);
    if (!val_res.is_valid) {
        if (val_res.error_message.find("is out of bounds") != std::string::npos) {
            throw std::out_of_range(val_res.error_message);
        }
        throw InvalidDownloadPreconditionException(val_res.error_message);
    }

    // 6. Fetch chunk from storage engine (DB connection released before S3 I/O)
    auto chunk_res = download_engine_->fetch_chunk(file_id, version_opt->version_number, chunk_index,
                                                   static_cast<uint64_t>(version_opt->encrypted_size));

    // ADR-010 flood-avoidance: emit file.download.initiated ONLY for chunk_index == 0
    if (chunk_index == 0) {
        const uint32_t total_chunks =
            calculate_expected_chunk_count(static_cast<uint64_t>(version_opt->encrypted_size));
        emit_download_initiated(audit_publisher_, file_id, caller_user_id, version_opt->version_number, 0,
                                total_chunks);
    }

    return DownloadChunkResult{.file_id = file_id,
                               .version_number = chunk_res.version_number,
                               .chunk_index = chunk_res.chunk_index,
                               .encrypted_data = std::move(chunk_res.encrypted_data),
                               .chunk_size_bytes = chunk_res.chunk_size_bytes,
                               .ciphertext_sha256 = std::move(chunk_res.ciphertext_sha256)};
}

std::optional<DownloadChunkResult> DownloadManager::get_chunk(const std::string& file_id, uint32_t chunk_index) {
    try {
        return get_chunk_versioned(file_id, 0, chunk_index, "");
    } catch (...) {
        return std::nullopt;
    }
}

DownloadResumeModel DownloadManager::prepare_resume_session(const std::string& file_id, int32_t version_number,
                                                            uint32_t starting_chunk,
                                                            const std::string& caller_user_id) {
    if (!pool_) {
        throw std::runtime_error("Database connection pool is uninitialized in DownloadManager");
    }

    std::optional<FileVersionEntity> version_opt;
    bool unauthorized = false;
    {
        auto conn = pool_->acquire();
        auto& default_conn = dynamic_cast<securecloud::files::db::DefaultDbConnection&>(*conn);
        pqxx::work tx(default_conn.native_handle());

        auto file_opt = file_repo_->find_by_id(file_id, tx);
        if (!file_opt) {
            throw FileNotFoundException("File not found: " + file_id);
        }

        bool is_trusted_peer = (caller_user_id.empty() || caller_user_id == "system" ||
                                caller_user_id == "authenticated_peer" || caller_user_id == "gateway");
        bool is_owner = (!caller_user_id.empty() && file_opt->owner_user_id == caller_user_id);
        bool has_read_perm = is_trusted_peer;
        if (!is_owner && !is_trusted_peer && !caller_user_id.empty()) {
            has_read_perm = access_repo_->check_access(file_id, caller_user_id, FilePermission::Read, tx);
        }
        if (!is_owner && !has_read_perm) {
            tx.abort();
            unauthorized = true;
        } else {
            if (file_opt->status != FileStatus::Available) {
                throw InvalidDownloadPreconditionException("File is not available for download; current status: " +
                                                           std::string(to_string(file_opt->status)));
            }

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
        }
    }

    if (unauthorized) {
        emit_download_denied(audit_publisher_, file_id, caller_user_id, "PrepareDownloadResume");
        throw UnauthorizedFileAccessException("Caller '" + caller_user_id + "' lacks READ access to file: " + file_id);
    }

    uint64_t total_bytes = static_cast<uint64_t>(version_opt->encrypted_size);
    uint32_t total_chunks =
        (total_bytes == 0) ? 0
                           : static_cast<uint32_t>((total_bytes + k_standard_chunk_size - 1) / k_standard_chunk_size);

    if (starting_chunk > 0 && starting_chunk >= total_chunks) {
        throw std::out_of_range("Starting chunk " + std::to_string(starting_chunk) + " is out of bounds for file " +
                                file_id + " (total chunks: " + std::to_string(total_chunks) + ")");
    }

    emit_download_initiated(audit_publisher_, file_id, caller_user_id, version_opt->version_number, starting_chunk,
                            total_chunks);

    return DownloadResumeModel{.file_id = file_id,
                               .version_number = version_opt->version_number,
                               .starting_chunk = starting_chunk,
                               .total_chunks = total_chunks,
                               .total_bytes = total_bytes,
                               .ciphertext_sha256 = version_opt->checksum_sha256};
}

} // namespace securecloud::files::service
