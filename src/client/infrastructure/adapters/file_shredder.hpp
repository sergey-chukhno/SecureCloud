#pragma once

#include "application/client_error.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace securecloud::client::infrastructure::adapters {

/// Configuration options for forensic file overwriting and destruction.
///
/// Media Note: On modern SSDs and copy-on-write filesystems (e.g. APFS, Btrfs),
/// physical flash wear-leveling may relocate blocks during in-place writes.
/// SecureCloud pairs multi-pass `FileShredder` overwrite + truncate + unlink with
/// SQLCipher 256-bit master-key destruction (`kMasterKeyId` purge in ISecureStorage)
/// for defense-in-depth across both HDD and SSD/CoW media.
struct ShredOptions {
    using PassObserver = std::function<void(uint32_t pass_index, const std::filesystem::path& path)>;

    static constexpr uint32_t kDefaultOverwritePasses = 3U;
    static constexpr std::size_t kDefaultChunkSizeBytes = 65536U;
    static constexpr std::size_t kMinChunkSizeBytes = 4096U;
    static constexpr std::size_t kMaxChunkSizeBytes = 16U * 1024U * 1024U;

    uint32_t overwrite_passes{kDefaultOverwritePasses};
    std::size_t chunk_size_bytes{kDefaultChunkSizeBytes};
    bool flush_to_disk{true};
    PassObserver pass_observer{};
};

struct ShredResult {
    std::size_t files_shredded{0};
    std::size_t bytes_overwritten{0};
    std::vector<std::string> failed_paths;
};

class FileShredder {
  public:
    /// Overwrites `path` cleanly using streaming bounded-memory passes
    /// (`0x00`, `0xFF`, and OpenSSL CSPRNG `RAND_bytes`), flushes to disk,
    /// truncates to zero bytes, and unlinks the file.
    /// Non-existent paths succeed as an idempotent `ok(0)`.
    static application::ClientResult<std::size_t> shred_file(const std::filesystem::path& path,
                                                             const ShredOptions& options = {});

    /// Best-effort batch shred over `paths`; does not abort early if one path fails.
    static application::ClientResult<ShredResult> shred_files(const std::vector<std::filesystem::path>& paths,
                                                              const ShredOptions& options = {});

    /// Scans regular files directly inside `dir` matching any suffix in `suffixes`
    /// (e.g. `.part`, `.log`, `-wal`, `-shm`, `.db`) and shreds all matches.
    static application::ClientResult<ShredResult> shred_directory_artifacts(const std::filesystem::path& dir,
                                                                            const std::vector<std::string>& suffixes,
                                                                            const ShredOptions& options = {});
};

} // namespace securecloud::client::infrastructure::adapters
