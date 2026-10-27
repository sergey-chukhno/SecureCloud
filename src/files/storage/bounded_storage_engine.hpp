#pragma once

#include "files/service/storage_engine.hpp"
#include "files/concurrency/concurrency_bulkhead.hpp"
#include "files/storage/s3_exceptions.hpp"

#include <memory>
#include <string>

namespace securecloud::files::storage {

/// Thrown when all storage permits are in use and acquisition times out (ADR-009, FILES-009).
class StorageCapacityExhaustedException : public S3ClientException {
  public:
    explicit StorageCapacityExhaustedException(const std::string& msg)
        : S3ClientException(msg) {}
};

/// Decorator around IStorageEngine that enforces strict bounded concurrency
/// on all underlying MinIO / S3 operations (FILES-009-T03).
class BoundedStorageEngine : public service::IStorageEngine {
  public:
    BoundedStorageEngine(std::shared_ptr<service::IStorageEngine> inner,
                         std::shared_ptr<ConcurrencyBulkhead> storage_bulkhead);
    ~BoundedStorageEngine() override = default;

    BoundedStorageEngine(const BoundedStorageEngine&) = delete;
    BoundedStorageEngine& operator=(const BoundedStorageEngine&) = delete;

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

    [[nodiscard]] std::shared_ptr<service::IStorageEngine> inner_engine() const noexcept { return inner_; }
    [[nodiscard]] std::shared_ptr<ConcurrencyBulkhead> bulkhead() const noexcept { return bulkhead_; }

  private:
    BulkheadPermit acquire_storage_permit();

    std::shared_ptr<service::IStorageEngine> inner_;
    std::shared_ptr<ConcurrencyBulkhead> bulkhead_;
};

} // namespace securecloud::files::storage
