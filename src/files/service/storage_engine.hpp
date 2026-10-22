#pragma once

#include "files/storage/s3_client.hpp"
#include "files/storage/s3_exceptions.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace securecloud::files::service {

/// Interface defining the object storage engine layer wrapping MinIO/S3.
/// Enforces opaque key derivation, cryptographic integrity verification, and zero-plaintext persistence.
class IStorageEngine {
  public:
    virtual ~IStorageEngine() = default;

    /// Stores an encrypted chunk object in S3.
    /// Derives opaque key: chunks/{transfer_id}/{chunk_index}.
    /// Validates payload SHA-256 against expected_sha256 (throws S3IntegrityException if mismatched).
    virtual bool put_chunk(const std::string& transfer_id, uint32_t chunk_index, std::string_view encrypted_data,
                           const std::string& expected_sha256) = 0;

    /// Retrieves an encrypted chunk object from S3.
    /// Returns std::nullopt if the chunk is not found.
    virtual std::optional<std::string> get_chunk(const std::string& transfer_id, uint32_t chunk_index) = 0;

    /// Deletes a specific chunk object from S3 idempotently.
    virtual bool delete_chunk(const std::string& transfer_id, uint32_t chunk_index) = 0;

    /// Stores a finalized encrypted file object in S3.
    /// Derives opaque key: objects/{file_id}/{version_number}.
    /// Validates payload SHA-256 against expected_sha256 (throws S3IntegrityException if mismatched).
    virtual bool put_file_object(const std::string& file_id, uint32_t version_number, std::string_view encrypted_data,
                                 const std::string& expected_sha256) = 0;

    /// Retrieves a finalized encrypted file object (or byte-range) from S3.
    /// Returns std::nullopt if the object is not found.
    virtual std::optional<std::string> get_file_object(const std::string& file_id, uint32_t version_number,
                                                       std::optional<storage::ByteRange> range = std::nullopt) = 0;

    /// Deletes all versions/objects associated with a file_id prefix.
    virtual bool delete_file_objects(const std::string& file_id) = 0;

    /// Deletes all chunk objects associated with an in-progress or abandoned transfer_id prefix.
    virtual bool delete_transfer_chunks(const std::string& transfer_id) = 0;
};

/// Production implementation of IStorageEngine wrapping S3Client.
class StorageEngine : public IStorageEngine {
  public:
    explicit StorageEngine(std::shared_ptr<storage::S3Client> s3_client = nullptr);
    ~StorageEngine() override = default;

    StorageEngine(const StorageEngine&) = delete;
    StorageEngine& operator=(const StorageEngine&) = delete;
    StorageEngine(StorageEngine&&) noexcept = default;
    StorageEngine& operator=(StorageEngine&&) noexcept = default;

    bool put_chunk(const std::string& transfer_id, uint32_t chunk_index, std::string_view encrypted_data,
                   const std::string& expected_sha256) override;

    std::optional<std::string> get_chunk(const std::string& transfer_id, uint32_t chunk_index) override;

    bool delete_chunk(const std::string& transfer_id, uint32_t chunk_index) override;

    bool put_file_object(const std::string& file_id, uint32_t version_number, std::string_view encrypted_data,
                         const std::string& expected_sha256) override;

    std::optional<std::string> get_file_object(const std::string& file_id, uint32_t version_number,
                                               std::optional<storage::ByteRange> range = std::nullopt) override;

    bool delete_file_objects(const std::string& file_id) override;

    bool delete_transfer_chunks(const std::string& transfer_id) override;

    [[nodiscard]] std::shared_ptr<storage::S3Client> s3_client() const noexcept { return s3_client_; }

    /// Derives opaque object key for a transfer chunk: chunks/{transfer_id}/{chunk_index}
    [[nodiscard]] static std::string derive_chunk_key(const std::string& transfer_id, uint32_t chunk_index);

    /// Derives opaque object key for a file object: objects/{file_id}/{version_number}
    [[nodiscard]] static std::string derive_file_object_key(const std::string& file_id, uint32_t version_number);

  private:
    std::shared_ptr<storage::S3Client> s3_client_;
};

} // namespace securecloud::files::service
