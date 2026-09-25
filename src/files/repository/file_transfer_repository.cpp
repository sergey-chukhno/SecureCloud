#include "files/repository/file_transfer_repository.hpp"

#include <chrono>

namespace securecloud::files {

FileTransferRepository::FileTransferRepository(std::shared_ptr<db::FilesDbConnectionPool> pool)
    : pool_(std::move(pool)) {}

void FileTransferRepository::create_transfer(const FileTransferEntity& transfer, pqxx::work& tx) {
    if (transfer.transfer_id.empty()) {
        throw RepositoryException("Transfer ID cannot be empty");
    }
    if (transfer.file_id.empty()) {
        throw RepositoryException("File ID cannot be empty");
    }
    if (transfer.initiator_user_id.empty()) {
        throw RepositoryException("Initiator user ID cannot be empty");
    }

    tx.exec_params(
        "INSERT INTO file_transfers (transfer_id, file_id, transfer_type, initiator_user_id, initiator_device_id, "
        "status, total_chunks, accepted_chunks, total_bytes, transferred_bytes, created_at, updated_at, expires_at) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        transfer.transfer_id,
        transfer.file_id,
        db::to_string(transfer.transfer_type),
        transfer.initiator_user_id,
        transfer.initiator_device_id,
        db::to_string(transfer.status),
        transfer.total_chunks,
        transfer.accepted_chunks,
        transfer.total_bytes,
        transfer.transferred_bytes,
        db::to_iso8601(transfer.created_at),
        db::to_iso8601(transfer.updated_at),
        db::to_iso8601(transfer.expires_at)
    );
}

std::optional<FileTransferEntity> FileTransferRepository::find_by_id(const std::string& transfer_id, pqxx::work& tx) {
    if (transfer_id.empty()) {
        return std::nullopt;
    }

    auto res = tx.exec_params(
        "SELECT transfer_id, file_id, transfer_type, initiator_user_id, initiator_device_id, status, "
        "total_chunks, accepted_chunks, total_bytes, transferred_bytes, created_at, updated_at, expires_at "
        "FROM file_transfers WHERE transfer_id = $1",
        transfer_id
    );

    if (res.empty()) {
        return std::nullopt;
    }

    return db::file_transfer_from_row(res[0]);
}

std::optional<FileTransferEntity> FileTransferRepository::find_by_id(const std::string& transfer_id) {
    pqxx::work tx;
    return find_by_id(transfer_id, tx);
}

bool FileTransferRepository::update_status(const std::string& transfer_id, TransferStatus status, pqxx::work& tx) {
    if (transfer_id.empty()) {
        return false;
    }

    auto now_iso = db::to_iso8601(std::chrono::system_clock::now());
    auto res = tx.exec_params(
        "UPDATE file_transfers SET status = $1, updated_at = $2 WHERE transfer_id = $3",
        db::to_string(status),
        now_iso,
        transfer_id
    );

    return res.affected_rows() > 0;
}

bool FileTransferRepository::update_status(const std::string& transfer_id, TransferStatus status) {
    pqxx::work tx;
    bool updated = update_status(transfer_id, status, tx);
    if (updated) {
        tx.commit();
    }
    return updated;
}

bool FileTransferRepository::increment_chunk_progress(const std::string& transfer_id, int64_t bytes_added, pqxx::work& tx) {
    if (transfer_id.empty()) {
        return false;
    }

    auto now_iso = db::to_iso8601(std::chrono::system_clock::now());
    auto res = tx.exec_params(
        "UPDATE file_transfers SET accepted_chunks = accepted_chunks + 1, transferred_bytes = transferred_bytes + $1, updated_at = $2 WHERE transfer_id = $3",
        bytes_added,
        now_iso,
        transfer_id
    );

    return res.affected_rows() > 0;
}

bool FileTransferRepository::increment_chunk_progress(const std::string& transfer_id, int64_t bytes_added) {
    pqxx::work tx;
    bool updated = increment_chunk_progress(transfer_id, bytes_added, tx);
    if (updated) {
        tx.commit();
    }
    return updated;
}

} // namespace securecloud::files
