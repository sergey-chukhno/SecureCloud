#include "bounded_storage_engine.hpp"

#include <stdexcept>
#include <utility>

namespace securecloud::files::storage {

BoundedStorageEngine::BoundedStorageEngine(std::shared_ptr<service::IStorageEngine> inner,
                                           std::shared_ptr<ConcurrencyBulkhead> storage_bulkhead)
    : inner_(std::move(inner)), bulkhead_(std::move(storage_bulkhead)) {
    if (!inner_) {
        throw std::invalid_argument("inner IStorageEngine must not be null");
    }
    if (!bulkhead_) {
        throw std::invalid_argument("storage ConcurrencyBulkhead must not be null");
    }
}

BulkheadPermit BoundedStorageEngine::acquire_storage_permit() {
    auto permit = bulkhead_->acquire_with_default_timeout();
    if (!permit) {
        throw StorageCapacityExhaustedException("Storage concurrency limit reached on domain '" +
                                                bulkhead_->domain_name() +
                                                "' (limit=" + std::to_string(bulkhead_->max_concurrency()) + ")");
    }
    return permit;
}

bool BoundedStorageEngine::put_chunk(const std::string& transfer_id, uint32_t chunk_index,
                                     std::string_view encrypted_data, const std::string& expected_sha256) {
    auto permit = acquire_storage_permit();
    return inner_->put_chunk(transfer_id, chunk_index, encrypted_data, expected_sha256);
}

std::optional<std::string> BoundedStorageEngine::get_chunk(const std::string& transfer_id, uint32_t chunk_index) {
    auto permit = acquire_storage_permit();
    return inner_->get_chunk(transfer_id, chunk_index);
}

bool BoundedStorageEngine::delete_chunk(const std::string& transfer_id, uint32_t chunk_index) {
    auto permit = acquire_storage_permit();
    return inner_->delete_chunk(transfer_id, chunk_index);
}

bool BoundedStorageEngine::put_file_object(const std::string& file_id, uint32_t version_number,
                                           std::string_view encrypted_data, const std::string& expected_sha256) {
    auto permit = acquire_storage_permit();
    return inner_->put_file_object(file_id, version_number, encrypted_data, expected_sha256);
}

std::optional<std::string> BoundedStorageEngine::get_file_object(const std::string& file_id, uint32_t version_number,
                                                                 std::optional<storage::ByteRange> range) {
    auto permit = acquire_storage_permit();
    return inner_->get_file_object(file_id, version_number, range);
}

bool BoundedStorageEngine::delete_file_objects(const std::string& file_id) {
    auto permit = acquire_storage_permit();
    return inner_->delete_file_objects(file_id);
}

bool BoundedStorageEngine::delete_transfer_chunks(const std::string& transfer_id) {
    auto permit = acquire_storage_permit();
    return inner_->delete_transfer_chunks(transfer_id);
}

} // namespace securecloud::files::storage
