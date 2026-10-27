#pragma once

#include "files/db/files_connection_pool.hpp"
#include "files/domain/chunk_validator.hpp"
#include "files/domain/file_chunk_entity.hpp"
#include "files/domain/file_transfer_entity.hpp"
#include "files/repository/file_chunk_repository.hpp"
#include "files/repository/file_repository.hpp"
#include "files/repository/file_transfer_repository.hpp"
#include "files/service/upload_session_manager.hpp"
#include "files/storage/s3_client.hpp"

#include <cstdint>
#include <memory>
#include <string>

namespace securecloud::files::service {

/// Result of storing and recording an encrypted chunk.
struct ChunkStoreResult {
    bool accepted{true};
    bool is_duplicate{false};
    std::string received_sha256;
    uint32_t chunk_index{0};
    int64_t bytes_written{0};
};

/// Authoritative Resumable Chunk Storage Engine & MinIO Chunk Staging Pipeline.
/// Enforces idempotent replays, out-of-order chunk staging, hash conflict detection,
/// and atomic progress accounting in PostgreSQL.
class ChunkStorageService {
  public:
    explicit ChunkStorageService(std::shared_ptr<db::FilesDbConnectionPool> pool,
                                 std::shared_ptr<storage::S3Client> s3_client,
                                 std::shared_ptr<FileTransferRepository> transfer_repo = nullptr,
                                 std::shared_ptr<FileChunkRepository> chunk_repo = nullptr,
                                 std::shared_ptr<FileRepository> file_repo = nullptr);

    virtual ~ChunkStorageService() = default;

    /// Stores and records an individual encrypted chunk with strict idempotency semantics.
    virtual ChunkStoreResult store_chunk(const ChunkPayloadDto& chunk_dto, const std::string& caller_user_id);

    /// Helper to compute the canonical MinIO staging object key.
    [[nodiscard]] static std::string build_staging_key(const std::string& upload_id, uint32_t chunk_index);

  private:
    std::shared_ptr<db::FilesDbConnectionPool> pool_;
    std::shared_ptr<storage::S3Client> s3_client_;
    std::shared_ptr<FileTransferRepository> transfer_repo_;
    std::shared_ptr<FileChunkRepository> chunk_repo_;
    std::shared_ptr<FileRepository> file_repo_;
};

} // namespace securecloud::files::service
