#include "files/service/storage_engine.hpp"

#include <algorithm>
#include <cctype>

namespace securecloud::files::service {

namespace {

std::string to_lower(std::string_view s) {
    std::string res;
    res.reserve(s.size());
    for (char c : s) {
        res.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return res;
}

} // namespace

StorageEngine::StorageEngine(std::shared_ptr<storage::S3Client> s3_client) : s3_client_(std::move(s3_client)) {}

std::string StorageEngine::derive_chunk_key(const std::string& transfer_id, uint32_t chunk_index) {
    return "chunks/" + transfer_id + "/" + std::to_string(chunk_index);
}

std::string StorageEngine::derive_file_object_key(const std::string& file_id, uint32_t version_number) {
    return "objects/" + file_id + "/" + std::to_string(version_number);
}

bool StorageEngine::put_chunk(const std::string& transfer_id, uint32_t chunk_index, std::string_view encrypted_data,
                              const std::string& expected_sha256) {
    if (!s3_client_) {
        throw storage::S3ClientException("StorageEngine: S3Client dependency is null");
    }

    const std::string actual_sha256 = storage::SigV4Signer::sha256_hex(encrypted_data);
    if (!expected_sha256.empty()) {
        if (to_lower(actual_sha256) != to_lower(expected_sha256)) {
            throw storage::S3IntegrityException("SHA-256 checksum mismatch on chunk upload: expected " +
                                                expected_sha256 + ", got " + actual_sha256);
        }
    }

    const std::string object_key = derive_chunk_key(transfer_id, chunk_index);
    return s3_client_->put_object(object_key, encrypted_data, "application/octet-stream", actual_sha256);
}

std::optional<std::string> StorageEngine::get_chunk(const std::string& transfer_id, uint32_t chunk_index) {
    if (!s3_client_) {
        throw storage::S3ClientException("StorageEngine: S3Client dependency is null");
    }

    const std::string object_key = derive_chunk_key(transfer_id, chunk_index);
    try {
        auto resp = s3_client_->get_object(object_key);
        return resp.body;
    } catch (const storage::S3ObjectNotFoundException&) {
        return std::nullopt;
    }
}

bool StorageEngine::delete_chunk(const std::string& transfer_id, uint32_t chunk_index) {
    if (!s3_client_) {
        throw storage::S3ClientException("StorageEngine: S3Client dependency is null");
    }

    const std::string object_key = derive_chunk_key(transfer_id, chunk_index);
    return s3_client_->delete_object(object_key);
}

bool StorageEngine::put_file_object(const std::string& file_id, uint32_t version_number,
                                    std::string_view encrypted_data, const std::string& expected_sha256) {
    if (!s3_client_) {
        throw storage::S3ClientException("StorageEngine: S3Client dependency is null");
    }

    const std::string actual_sha256 = storage::SigV4Signer::sha256_hex(encrypted_data);
    if (!expected_sha256.empty()) {
        if (to_lower(actual_sha256) != to_lower(expected_sha256)) {
            throw storage::S3IntegrityException("SHA-256 checksum mismatch on file object upload: expected " +
                                                expected_sha256 + ", got " + actual_sha256);
        }
    }

    const std::string object_key = derive_file_object_key(file_id, version_number);
    return s3_client_->put_object(object_key, encrypted_data, "application/octet-stream", actual_sha256);
}

std::optional<std::string> StorageEngine::get_file_object(const std::string& file_id, uint32_t version_number,
                                                          std::optional<storage::ByteRange> range) {
    if (!s3_client_) {
        throw storage::S3ClientException("StorageEngine: S3Client dependency is null");
    }

    const std::string object_key = derive_file_object_key(file_id, version_number);
    try {
        auto resp = s3_client_->get_object(object_key, range);
        return resp.body;
    } catch (const storage::S3ObjectNotFoundException&) {
        return std::nullopt;
    }
}

bool StorageEngine::delete_file_objects(const std::string& file_id) {
    if (!s3_client_) {
        throw storage::S3ClientException("StorageEngine: S3Client dependency is null");
    }

    const std::string prefix = "objects/" + file_id + "/";
    std::string continuation_token;
    do {
        auto res = s3_client_->list_objects(prefix, 1000, continuation_token);
        for (const auto& obj : res.objects) {
            s3_client_->delete_object(obj.key);
        }
        continuation_token = res.next_continuation_token;
    } while (!continuation_token.empty());

    return true;
}

bool StorageEngine::delete_transfer_chunks(const std::string& transfer_id) {
    if (!s3_client_) {
        throw storage::S3ClientException("StorageEngine: S3Client dependency is null");
    }

    const std::string prefix = "chunks/" + transfer_id + "/";
    std::string continuation_token;
    do {
        auto res = s3_client_->list_objects(prefix, 1000, continuation_token);
        for (const auto& obj : res.objects) {
            s3_client_->delete_object(obj.key);
        }
        continuation_token = res.next_continuation_token;
    } while (!continuation_token.empty());

    return true;
}

} // namespace securecloud::files::service
