#include "files/repository/file_chunk_repository.hpp"

#include <chrono>

namespace securecloud::files {

FileChunkRepository::FileChunkRepository(std::shared_ptr<db::FilesDbConnectionPool> pool)
    : pool_(std::move(pool)) {}

ChunkRecordResult FileChunkRepository::record_chunk(const FileChunkEntity& chunk, pqxx::work& tx) {
    if (chunk.chunk_id.empty() || chunk.transfer_id.empty()) {
        throw RepositoryException("Chunk ID and Transfer ID must not be empty");
    }
    if (chunk.chunk_index < 0) {
        throw RepositoryException("Chunk index cannot be negative");
    }
    if (chunk.chunk_size < 0) {
        throw RepositoryException("Chunk size cannot be negative");
    }
    if (chunk.chunk_hash_sha256.empty()) {
        throw RepositoryException("Chunk SHA-256 hash must not be empty");
    }

    auto res = tx.exec_params(
        "INSERT INTO file_chunks (chunk_id, transfer_id, chunk_index, byte_offset, chunk_size, chunk_hash_sha256, minio_chunk_key, status, created_at) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) "
        "ON CONFLICT (transfer_id, chunk_index) DO NOTHING",
        chunk.chunk_id,
        chunk.transfer_id,
        chunk.chunk_index,
        chunk.byte_offset,
        chunk.chunk_size,
        chunk.chunk_hash_sha256,
        chunk.minio_chunk_key,
        db::to_string(chunk.status),
        db::to_iso8601(chunk.created_at)
    );

    if (res.affected_rows() > 0) {
        return ChunkRecordResult::NewlyInserted;
    }

    // A conflict occurred on (transfer_id, chunk_index). Query the existing chunk's hash.
    auto check_res = tx.exec_params(
        "SELECT chunk_hash_sha256 FROM file_chunks WHERE transfer_id = $1 AND chunk_index = $2",
        chunk.transfer_id,
        chunk.chunk_index
    );

    if (check_res.empty()) {
        throw RepositoryException("Conflict detected on chunk insert but existing chunk record was not found");
    }

    std::string existing_hash = check_res[0]["chunk_hash_sha256"].c_str();
    if (existing_hash == chunk.chunk_hash_sha256) {
        return ChunkRecordResult::AlreadyExistsIdentical;
    }

    throw ChunkIntegrityException(
        "Chunk hash mismatch for transfer '" + chunk.transfer_id + "', chunk index " +
        std::to_string(chunk.chunk_index) + ": existing hash '" + existing_hash +
        "', incoming hash '" + chunk.chunk_hash_sha256 + "'");
}

std::vector<int32_t> FileChunkRepository::get_accepted_chunk_indices(const std::string& transfer_id, pqxx::work& tx) {
    if (transfer_id.empty()) {
        return {};
    }

    auto res = tx.exec_params(
        "SELECT chunk_index FROM file_chunks WHERE transfer_id = $1 ORDER BY chunk_index ASC",
        transfer_id
    );

    std::vector<int32_t> indices;
    indices.reserve(res.size());
    for (size_t i = 0; i < res.size(); ++i) {
        indices.push_back(std::stoi(res[i]["chunk_index"].c_str()));
    }
    return indices;
}

std::vector<int32_t> FileChunkRepository::get_accepted_chunk_indices(const std::string& transfer_id) {
    pqxx::work tx;
    return get_accepted_chunk_indices(transfer_id, tx);
}

int32_t FileChunkRepository::count_accepted_chunks(const std::string& transfer_id, pqxx::work& tx) {
    if (transfer_id.empty()) {
        return 0;
    }

    auto res = tx.exec_params(
        "SELECT COUNT(*) FROM file_chunks WHERE transfer_id = $1",
        transfer_id
    );

    if (res.empty()) {
        return 0;
    }

    return std::stoi(res[0]["count"].c_str());
}

int32_t FileChunkRepository::count_accepted_chunks(const std::string& transfer_id) {
    pqxx::work tx;
    return count_accepted_chunks(transfer_id, tx);
}

bool FileChunkRepository::is_chunk_present(const std::string& transfer_id, int32_t chunk_index, pqxx::work& tx) {
    if (transfer_id.empty() || chunk_index < 0) {
        return false;
    }

    auto res = tx.exec_params(
        "SELECT 1 FROM file_chunks WHERE transfer_id = $1 AND chunk_index = $2",
        transfer_id,
        chunk_index
    );

    return !res.empty();
}

bool FileChunkRepository::is_chunk_present(const std::string& transfer_id, int32_t chunk_index) {
    pqxx::work tx;
    return is_chunk_present(transfer_id, chunk_index, tx);
}

std::vector<FileChunkEntity> FileChunkRepository::list_chunks_for_transfer(const std::string& transfer_id, pqxx::work& tx) {
    if (transfer_id.empty()) {
        return {};
    }

    auto res = tx.exec_params(
        "SELECT chunk_id, transfer_id, chunk_index, byte_offset, chunk_size, chunk_hash_sha256, minio_chunk_key, status, created_at "
        "FROM file_chunks WHERE transfer_id = $1 ORDER BY chunk_index ASC",
        transfer_id
    );

    std::vector<FileChunkEntity> chunks;
    chunks.reserve(res.size());
    for (size_t i = 0; i < res.size(); ++i) {
        chunks.push_back(db::file_chunk_from_row(res[i]));
    }
    return chunks;
}

std::vector<FileChunkEntity> FileChunkRepository::list_chunks_for_transfer(const std::string& transfer_id) {
    pqxx::work tx;
    return list_chunks_for_transfer(transfer_id, tx);
}

} // namespace securecloud::files
