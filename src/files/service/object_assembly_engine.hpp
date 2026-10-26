#pragma once

#include "files/domain/file_chunk_entity.hpp"
#include "files/storage/s3_client.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace securecloud::files::service {

/// Result of whole-object assembly from staged chunks.
struct AssemblyResult {
    std::string target_object_key;
    uint64_t total_bytes{0};
    std::string computed_sha256;
};

/// Engine responsible for assembling an immutable file version object from ordered
/// staged chunks and cleaning up staging resources upon durable commit.
class ObjectAssemblyEngine {
  public:
    explicit ObjectAssemblyEngine(std::shared_ptr<storage::S3Client> s3_client);
    virtual ~ObjectAssemblyEngine() = default;

    ObjectAssemblyEngine(const ObjectAssemblyEngine&) = delete;
    ObjectAssemblyEngine& operator=(const ObjectAssemblyEngine&) = delete;
    ObjectAssemblyEngine(ObjectAssemblyEngine&&) noexcept = default;
    ObjectAssemblyEngine& operator=(ObjectAssemblyEngine&&) noexcept = default;

    /// Assembles an immutable target version object from ordered staged chunks.
    /// Reads staged chunks in ascending index order, concatenates their payloads,
    /// verifies cumulative whole-object SHA-256 digest, and writes the assembled
    /// whole object to objects/{file_id}/{target_version}.
    /// Throws S3Exception derivatives on retrieval or upload failures.
    virtual AssemblyResult assemble_version_object(
        const std::string& file_id,
        uint32_t target_version,
        const std::string& transfer_id,
        const std::vector<FileChunkEntity>& ordered_chunks);

    /// Cleans up temporary staged chunks from S3 after durable persistence.
    /// Safe, idempotent, best-effort: failure to delete a staging chunk logs a warning
    /// and does not fail the operation.
    virtual void cleanup_staging_chunks(
        const std::string& transfer_id,
        const std::vector<FileChunkEntity>& ordered_chunks) noexcept;

    /// Derives canonical version object key: objects/{file_id}/{target_version}
    [[nodiscard]] static std::string build_version_key(const std::string& file_id, uint32_t target_version);

  private:
    std::shared_ptr<storage::S3Client> s3_client_;
};

} // namespace securecloud::files::service
