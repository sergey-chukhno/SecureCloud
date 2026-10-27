#include "files/service/object_assembly_engine.hpp"

#include "files/domain/chunk_validator.hpp"
#include "files/storage/s3_exceptions.hpp"

#include <algorithm>
#include <iostream>

namespace securecloud::files::service {

ObjectAssemblyEngine::ObjectAssemblyEngine(std::shared_ptr<storage::S3Client> s3_client)
    : s3_client_(std::move(s3_client)) {}

std::string ObjectAssemblyEngine::build_version_key(const std::string& file_id, uint32_t target_version) {
    return "objects/" + file_id + "/" + std::to_string(target_version);
}

AssemblyResult ObjectAssemblyEngine::assemble_version_object(const std::string& file_id, uint32_t target_version,
                                                             const std::string& transfer_id,
                                                             const std::vector<FileChunkEntity>& ordered_chunks) {
    (void)transfer_id;

    if (!s3_client_) {
        throw storage::S3ClientException("S3Client is uninitialized in ObjectAssemblyEngine");
    }

    std::string target_key = build_version_key(file_id, target_version);

    if (ordered_chunks.empty()) {
        std::string empty_hash = compute_sha256_hex("");
        s3_client_->put_object(target_key, "", "application/octet-stream", empty_hash);
        return AssemblyResult{.target_object_key = target_key, .total_bytes = 0, .computed_sha256 = empty_hash};
    }

    auto sorted_chunks = ordered_chunks;
    std::sort(sorted_chunks.begin(), sorted_chunks.end(),
              [](const FileChunkEntity& a, const FileChunkEntity& b) { return a.chunk_index < b.chunk_index; });

    size_t total_expected_bytes = 0;
    for (const auto& c : sorted_chunks) {
        total_expected_bytes += static_cast<size_t>(std::max(0, c.chunk_size));
    }

    std::string assembled_payload;
    assembled_payload.reserve(total_expected_bytes);

    for (const auto& chunk : sorted_chunks) {
        auto resp = s3_client_->get_object(chunk.minio_chunk_key);

        // Verify retrieved chunk hash matches recorded chunk hash
        std::string chunk_hash = compute_sha256_hex(resp.body);
        bool match = (chunk_hash.size() == chunk.chunk_hash_sha256.size());
        if (match) {
            for (size_t i = 0; i < chunk_hash.size(); ++i) {
                if (std::tolower(static_cast<unsigned char>(chunk_hash[i])) !=
                    std::tolower(static_cast<unsigned char>(chunk.chunk_hash_sha256[i]))) {
                    match = false;
                    break;
                }
            }
        }

        if (!match) {
            throw storage::S3IntegrityException("Staged chunk corrupted: computed hash (" + chunk_hash +
                                                ") does not match recorded chunk hash (" + chunk.chunk_hash_sha256 +
                                                ") for key " + chunk.minio_chunk_key);
        }

        assembled_payload.append(resp.body);
    }

    std::string computed_whole_sha256 = compute_sha256_hex(assembled_payload);

    s3_client_->put_object(target_key, assembled_payload, "application/octet-stream", computed_whole_sha256);

    return AssemblyResult{.target_object_key = target_key,
                          .total_bytes = static_cast<uint64_t>(assembled_payload.size()),
                          .computed_sha256 = computed_whole_sha256};
}

void ObjectAssemblyEngine::cleanup_staging_chunks(const std::string& transfer_id,
                                                  const std::vector<FileChunkEntity>& ordered_chunks) noexcept {
    (void)transfer_id;
    if (!s3_client_) {
        return;
    }

    for (const auto& chunk : ordered_chunks) {
        try {
            if (!chunk.minio_chunk_key.empty()) {
                s3_client_->delete_object(chunk.minio_chunk_key);
            }
        } catch (const std::exception& e) {
            std::cerr << "[ObjectAssemblyEngine] Warning: failed to delete staging chunk " << chunk.minio_chunk_key
                      << ": " << e.what() << "\n";
        } catch (...) {
            std::cerr << "[ObjectAssemblyEngine] Warning: unknown failure deleting staging chunk "
                      << chunk.minio_chunk_key << "\n";
        }
    }
}

} // namespace securecloud::files::service
