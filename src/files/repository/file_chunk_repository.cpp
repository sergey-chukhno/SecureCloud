#include "files/repository/file_chunk_repository.hpp"

#include "files/db/files_connection_pool.hpp"

#include <chrono>
#include <cstddef>

namespace securecloud::files {

#if defined(SECURECLOUD_FILES_TEST_PQXX)
FileChunkRepository::FileChunkRepository(std::shared_ptr<db::FilesDbConnectionPool> pool)
    : pool_(pool ? std::move(pool) : db::test_files_db_connection_pool()) {}
#else
FileChunkRepository::FileChunkRepository(std::shared_ptr<db::FilesDbConnectionPool> pool) : pool_(std::move(pool)) {}
#endif

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

    auto res = tx.exec("INSERT INTO file_chunks (chunk_id, transfer_id, chunk_index, byte_offset, chunk_size, "
                       "chunk_hash_sha256, minio_chunk_key, status, created_at) "
                       "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) "
                       "ON CONFLICT (transfer_id, chunk_index) DO NOTHING",
                       pqxx::params{chunk.chunk_id, chunk.transfer_id, chunk.chunk_index, chunk.byte_offset,
                                    chunk.chunk_size, chunk.chunk_hash_sha256, chunk.minio_chunk_key,
                                    db::to_string(chunk.status), db::to_iso8601(chunk.created_at)});

    if (res.affected_rows() > 0) {
        return ChunkRecordResult::NewlyInserted;
    }

    // A conflict occurred on (transfer_id, chunk_index). Query the existing chunk's hash.
    auto check_res = tx.exec("SELECT chunk_hash_sha256 FROM file_chunks WHERE transfer_id = $1 AND chunk_index = $2",
                             pqxx::params{chunk.transfer_id, chunk.chunk_index});

    if (check_res.empty()) {
        throw RepositoryException("Conflict detected on chunk insert but existing chunk record was not found");
    }

    std::string existing_hash = check_res[0]["chunk_hash_sha256"].c_str();
    if (existing_hash == chunk.chunk_hash_sha256) {
        return ChunkRecordResult::AlreadyExistsIdentical;
    }

    throw ChunkIntegrityException("Chunk hash mismatch for transfer '" + chunk.transfer_id + "', chunk index " +
                                  std::to_string(chunk.chunk_index) + ": existing hash '" + existing_hash +
                                  "', incoming hash '" + chunk.chunk_hash_sha256 + "'");
}

std::vector<int32_t> FileChunkRepository::get_accepted_chunk_indices(const std::string& transfer_id, pqxx::work& tx) {
    if (transfer_id.empty()) {
        return {};
    }

    auto res = tx.exec("SELECT chunk_index FROM file_chunks WHERE transfer_id = $1 ORDER BY chunk_index ASC",
                       pqxx::params{transfer_id});

    std::vector<int32_t> indices;
    indices.reserve(static_cast<size_t>(res.size()));
    for (decltype(res.size()) i = 0; i < res.size(); ++i) {
        indices.push_back(std::stoi(res[i]["chunk_index"].c_str()));
    }
    return indices;
}

std::vector<int32_t> FileChunkRepository::get_accepted_chunk_indices(const std::string& transfer_id) {
    if (!pool_)
        throw RepositoryException("Connection pool not initialized");
    auto lease = pool_->acquire();
    auto* pg_conn = dynamic_cast<db::DefaultDbConnection*>(lease.get());
    if (!pg_conn)
        throw RepositoryException("Database connection is not a PostgreSQL connection");

    pqxx::work tx(pg_conn->native_handle());
    auto result = get_accepted_chunk_indices(transfer_id, tx);
    tx.commit();
    return result;
}

int32_t FileChunkRepository::count_accepted_chunks(const std::string& transfer_id, pqxx::work& tx) {
    if (transfer_id.empty()) {
        return 0;
    }

    auto res = tx.exec("SELECT COUNT(*) FROM file_chunks WHERE transfer_id = $1", pqxx::params{transfer_id});

    if (res.empty()) {
        return 0;
    }

    return std::stoi(res[0]["count"].c_str());
}

int32_t FileChunkRepository::count_accepted_chunks(const std::string& transfer_id) {
    if (!pool_)
        throw RepositoryException("Connection pool not initialized");
    auto lease = pool_->acquire();
    auto* pg_conn = dynamic_cast<db::DefaultDbConnection*>(lease.get());
    if (!pg_conn)
        throw RepositoryException("Database connection is not a PostgreSQL connection");

    pqxx::work tx(pg_conn->native_handle());
    auto result = count_accepted_chunks(transfer_id, tx);
    tx.commit();
    return result;
}

bool FileChunkRepository::is_chunk_present(const std::string& transfer_id, int32_t chunk_index, pqxx::work& tx) {
    if (transfer_id.empty() || chunk_index < 0) {
        return false;
    }

    auto res = tx.exec("SELECT 1 FROM file_chunks WHERE transfer_id = $1 AND chunk_index = $2",
                       pqxx::params{transfer_id, chunk_index});

    return !res.empty();
}

bool FileChunkRepository::is_chunk_present(const std::string& transfer_id, int32_t chunk_index) {
    if (!pool_)
        throw RepositoryException("Connection pool not initialized");
    auto lease = pool_->acquire();
    auto* pg_conn = dynamic_cast<db::DefaultDbConnection*>(lease.get());
    if (!pg_conn)
        throw RepositoryException("Database connection is not a PostgreSQL connection");

    pqxx::work tx(pg_conn->native_handle());
    bool result = is_chunk_present(transfer_id, chunk_index, tx);
    tx.commit();
    return result;
}

std::vector<FileChunkEntity> FileChunkRepository::list_chunks_for_transfer(const std::string& transfer_id,
                                                                           pqxx::work& tx) {
    if (transfer_id.empty()) {
        return {};
    }

    auto res = tx.exec("SELECT chunk_id, transfer_id, chunk_index, byte_offset, chunk_size, chunk_hash_sha256, "
                       "minio_chunk_key, status, created_at "
                       "FROM file_chunks WHERE transfer_id = $1 ORDER BY chunk_index ASC",
                       pqxx::params{transfer_id});

    std::vector<FileChunkEntity> chunks;
    chunks.reserve(static_cast<size_t>(res.size()));
    for (decltype(res.size()) i = 0; i < res.size(); ++i) {
        chunks.push_back(db::file_chunk_from_row(pqxx::row(res[i])));
    }
    return chunks;
}

std::vector<FileChunkEntity> FileChunkRepository::list_chunks_for_transfer(const std::string& transfer_id) {
    if (!pool_)
        throw RepositoryException("Connection pool not initialized");
    auto lease = pool_->acquire();
    auto* pg_conn = dynamic_cast<db::DefaultDbConnection*>(lease.get());
    if (!pg_conn)
        throw RepositoryException("Database connection is not a PostgreSQL connection");

    pqxx::work tx(pg_conn->native_handle());
    auto result = list_chunks_for_transfer(transfer_id, tx);
    tx.commit();
    return result;
}

} // namespace securecloud::files
