#pragma once

#include "files/db/pqxx_compat.hpp"
#include "files/domain/encrypted_file_metadata_entity.hpp"
#include "files/domain/file_access_entity.hpp"
#include "files/domain/file_chunk_entity.hpp"
#include "files/domain/file_entity.hpp"
#include "files/domain/file_transfer_entity.hpp"
#include "files/domain/file_version_entity.hpp"
#include "files/domain/files_outbox_entity.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::files::db {

// --- Mapper Exceptions ---

class MappingException : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

class InvalidEnumException : public MappingException {
    using MappingException::MappingException;
};

class TimestampParseException : public MappingException {
    using MappingException::MappingException;
};

class ByteaParseException : public MappingException {
    using MappingException::MappingException;
};

// --- Strong Enum <-> String Conversions ---

std::string to_string(FileStatus status);
FileStatus file_status_from_string(std::string_view str);

std::string to_string(TransferType type);
TransferType transfer_type_from_string(std::string_view str);

std::string to_string(TransferStatus status);
TransferStatus transfer_status_from_string(std::string_view str);

std::string to_string(ChunkStatus status);
ChunkStatus chunk_status_from_string(std::string_view str);

std::string to_string(FilePermission permission);
FilePermission file_permission_from_string(std::string_view str);

std::string to_string(OutboxStatus status);
OutboxStatus outbox_status_from_string(std::string_view str);

// --- Timestamp Conversions ---

std::string to_iso8601(std::chrono::system_clock::time_point tp);
std::chrono::system_clock::time_point from_iso8601(std::string_view str);

// --- PostgreSQL Bytea Conversions ---

std::string to_bytea_hex(const std::vector<uint8_t>& bytes);
std::vector<uint8_t> from_bytea_hex(std::string_view hex_str);

// --- Entity Row Mappers ---

[[nodiscard]] FileEntity file_from_row(const pqxx::row& row);
[[nodiscard]] FileVersionEntity file_version_from_row(const pqxx::row& row);
[[nodiscard]] EncryptedFileMetadataEntity encrypted_metadata_from_row(const pqxx::row& row);
[[nodiscard]] FileTransferEntity file_transfer_from_row(const pqxx::row& row);
[[nodiscard]] FileChunkEntity file_chunk_from_row(const pqxx::row& row);
[[nodiscard]] FileAccessEntity file_access_from_row(const pqxx::row& row);
[[nodiscard]] FilesOutboxEntity files_outbox_from_row(const pqxx::row& row);

// --- Test Helper Row Builder ---

class RowBuilder {
  public:
    RowBuilder& set(std::string name, std::string value);
    RowBuilder& set_null(std::string name);
    [[nodiscard]] pqxx::row build() const;

  private:
    std::vector<std::pair<std::string, std::optional<std::string>>> columns_;
};

} // namespace securecloud::files::db
