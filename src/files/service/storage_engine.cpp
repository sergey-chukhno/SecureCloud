#include "files/service/storage_engine.hpp"

#include <algorithm>
#include <cctype>

namespace securecloud::files::service {

namespace {

std::string to_lower(std::string_view str) {
    std::string result;
    result.reserve(str.size());
    for (char c : str) {
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return result;
}

} // namespace

StorageEngine::StorageEngine(std::shared_ptr<storage::S3Client> s3_client) : s3_client_(std::move(s3_client)) {
    if (!s3_client_) {
        throw storage::S3ClientException("StorageEngine requires a non-null S3Client instance");
    }
}

std::string StorageEngine::chunk_key(const std::string& transfer_id, uint32_t chunk_index) {
    return "chunks/" + transfer_id + "/" + std::to_string(chunk_index);
}

std::string StorageEngine::object_key(const std::string& file_id, uint32_t version_number) {
    return "objects/" + file_id + "/" + std::to_string(version_number);
}

bool StorageEngine::put_chunk(const std::string& transfer_id, uint32_t chunk_index, std::string_view encrypted_data,
                              const std::string& expected_sha256) {
    const std::string computed_hash = storage::SigV4Signer::sha256_hex(encrypted_data);

    if (!expected_sha256.empty()) {
        if (to_lower(computed_hash) != to_lower(expected_sha256)) {
            throw storage::S3IntegrityException("SHA-256 integrity mismatch for chunk (" + transfer_id + ", " +
                                                std::to_string(chunk_index) + "): expected " + expected_sha256 +
                                                " but computed " + computed_hash);
        }
    }

    const std::string key = chunk_key(transfer_id, chunk_index);
    return s3_client_->put_object(key, encrypted_data, "application/octet-stream", computed_hash);
}

std::optional<std::string> StorageEngine::get_chunk(const std::string& transfer_id, uint32_t chunk_index) {
    const std::string key = chunk_key(transfer_id, chunk_index);
    try {
        const auto res = s3_client_->get_object(key);
        return res.body;
    } catch (const storage::S3ObjectNotFoundException&) {
        return std::nullopt;
    }
}

bool StorageEngine::delete_chunk(const std::string& transfer_id, uint32_t chunk_index) {
    const std::string key = chunk_key(transfer_id, chunk_index);
    return s3_client_->delete_object(key);
}

bool StorageEngine::put_file_object(const std::string& file_id, uint32_t version_number,
                                    std::string_view encrypted_data, const std::string& expected_sha256) {
    const std::string computed_hash = storage::SigV4Signer::sha256_hex(encrypted_data);

    if (!expected_sha256.empty()) {
        if (to_lower(computed_hash) != to_lower(expected_sha256)) {
            throw storage::S3IntegrityException("SHA-256 integrity mismatch for file (" + file_id + ", v" +
                                                std::to_string(version_number) + "): expected " + expected_sha256 +
                                                " but computed " + computed_hash);
        }
    }

    const std::string key = object_key(file_id, version_number);
    return s3_client_->put_object(key, encrypted_data, "application/octet-stream", computed_hash);
}

std::optional<std::string> StorageEngine::get_file_object(const std::string& file_id, uint32_t version_number,
                                                          std::optional<storage::ByteRange> range) {
    const std::string key = object_key(file_id, version_number);
    try {
        const auto res = s3_client_->get_object(key, range);
        return res.body;
    } catch (const storage::S3ObjectNotFoundException&) {
        return std::nullopt;
    }
}

bool StorageEngine::delete_file_objects(const std::string& file_id) {
    const std::string prefix = "objects/" + file_id + "/";
    const auto list_res = s3_client_->list_objects(prefix);
    for (const auto& obj : list_res.objects) {
        s3_client_->delete_object(obj.key);
    }
    return true;
}

bool StorageEngine::delete_transfer_chunks(const std::string& transfer_id) {
    const std::string prefix = "chunks/" + transfer_id + "/";
    const auto list_res = s3_client_->list_objects(prefix);
    for (const auto& obj : list_res.objects) {
        s3_client_->delete_object(obj.key);
    }
    return true;
}

} // namespace securecloud::files::service
