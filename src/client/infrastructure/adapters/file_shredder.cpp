#include "infrastructure/adapters/file_shredder.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <limits>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <vector>

#if defined(_WIN32)
#include <cstdio>
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace securecloud::client::infrastructure::adapters {
namespace {

constexpr std::size_t kMaxDirectoryEntries = 10000U;

class BufferCleanseGuard {
  public:
    explicit BufferCleanseGuard(std::vector<uint8_t>& buf) noexcept : buf_(buf) {}
    ~BufferCleanseGuard() {
        if (!buf_.empty()) {
            OPENSSL_cleanse(buf_.data(), buf_.size());
            buf_.clear();
        }
    }

    BufferCleanseGuard(const BufferCleanseGuard&) = delete;
    BufferCleanseGuard& operator=(const BufferCleanseGuard&) = delete;

  private:
    std::vector<uint8_t>& buf_;
};

#if defined(_WIN32)
class FileHandleGuard {
  public:
    explicit FileHandleGuard(std::FILE* fp) noexcept : fp_(fp) {}
    ~FileHandleGuard() { reset(); }

    FileHandleGuard(const FileHandleGuard&) = delete;
    FileHandleGuard& operator=(const FileHandleGuard&) = delete;

    [[nodiscard]] std::FILE* get() const noexcept { return fp_; }
    void reset() noexcept {
        if (fp_ != nullptr) {
            std::fclose(fp_);
            fp_ = nullptr;
        }
    }

  private:
    std::FILE* fp_{nullptr};
};
#else
class PosixFdGuard {
  public:
    explicit PosixFdGuard(int fd) noexcept : fd_(fd) {}
    ~PosixFdGuard() { reset(); }

    PosixFdGuard(const PosixFdGuard&) = delete;
    PosixFdGuard& operator=(const PosixFdGuard&) = delete;

    [[nodiscard]] int get() const noexcept { return fd_; }
    void reset() noexcept {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

  private:
    int fd_{-1};
};
#endif

bool ends_with(std::string_view value, std::string_view suffix) noexcept {
    return suffix.size() <= value.size() && value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

application::ClientResult<void> fill_pass_buffer(uint32_t pass_index, std::vector<uint8_t>& buffer,
                                                 std::size_t bytes_needed) {
    if (pass_index == 0U) {
        std::fill_n(buffer.data(), bytes_needed, static_cast<uint8_t>(0x00));
        return application::ClientResult<void>::ok();
    }
    if (pass_index == 1U) {
        std::fill_n(buffer.data(), bytes_needed, static_cast<uint8_t>(0xFF));
        return application::ClientResult<void>::ok();
    }
    if (bytes_needed > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return application::ClientResult<void>::error(
            application::ClientError::crypto("Chunk size exceeds OpenSSL RAND_bytes limit"));
    }
    if (RAND_bytes(buffer.data(), static_cast<int>(bytes_needed)) != 1) {
        return application::ClientResult<void>::error(
            application::ClientError::crypto("OpenSSL RAND_bytes failed while shredding file"));
    }
    return application::ClientResult<void>::ok();
}

} // namespace

application::ClientResult<std::size_t> FileShredder::shred_file(const std::filesystem::path& path,
                                                                const ShredOptions& options) {
    if (path.empty()) {
        return application::ClientResult<std::size_t>::error(
            application::ClientError::validation("Target path for shredding cannot be empty"));
    }

    std::error_code ec;
    const bool exists = std::filesystem::exists(path, ec);
    if (ec) {
        return application::ClientResult<std::size_t>::error(
            application::ClientError::storage("Failed to stat file for shredding: " + ec.message()));
    }
    if (!exists) {
        return application::ClientResult<std::size_t>::ok(0U);
    }

    if (std::filesystem::is_directory(path, ec)) {
        return application::ClientResult<std::size_t>::error(
            application::ClientError::validation("Cannot shred a directory directly: " + path.string()));
    }
    if (ec) {
        return application::ClientResult<std::size_t>::error(
            application::ClientError::storage("Failed to inspect file type for shredding: " + ec.message()));
    }

    const std::uintmax_t raw_size = std::filesystem::file_size(path, ec);
    if (ec) {
        return application::ClientResult<std::size_t>::error(
            application::ClientError::storage("Failed to read file size for shredding: " + ec.message()));
    }
    if (raw_size > static_cast<std::uintmax_t>(std::numeric_limits<std::size_t>::max())) {
        return application::ClientResult<std::size_t>::error(
            application::ClientError::storage("File exceeds supported size_t range for shredding"));
    }
    const std::size_t file_size = static_cast<std::size_t>(raw_size);

    std::size_t total_bytes_overwritten = 0U;

    if (file_size > 0U) {
        const uint32_t passes = std::max<uint32_t>(1U, options.overwrite_passes);
        const std::size_t bounded_chunk =
            std::clamp(options.chunk_size_bytes, ShredOptions::kMinChunkSizeBytes, ShredOptions::kMaxChunkSizeBytes);
        const std::size_t buffer_size = std::min(bounded_chunk, file_size);

        std::vector<uint8_t> buffer(buffer_size);
        BufferCleanseGuard buffer_guard(buffer);

#if defined(_WIN32)
        const std::string path_utf8 = path.string();
        FileHandleGuard fp_guard(std::fopen(path_utf8.c_str(), "r+b"));
        if (fp_guard.get() == nullptr) {
            return application::ClientResult<std::size_t>::error(application::ClientError::storage(
                "Failed to open file for shredding: " + std::string(std::strerror(errno))));
        }

        for (uint32_t pass = 0U; pass < passes; ++pass) {
            std::rewind(fp_guard.get());
            std::size_t remaining = file_size;
            while (remaining > 0U) {
                const std::size_t to_write = std::min(remaining, buffer.size());
                const auto fill_res = fill_pass_buffer(pass, buffer, to_write);
                if (fill_res.is_error()) {
                    return application::ClientResult<std::size_t>::error(fill_res.error());
                }
                const std::size_t written = std::fwrite(buffer.data(), 1U, to_write, fp_guard.get());
                if (written != to_write) {
                    return application::ClientResult<std::size_t>::error(
                        application::ClientError::storage("Short write while shredding file"));
                }
                remaining -= to_write;
                total_bytes_overwritten += to_write;
            }
            if (std::fflush(fp_guard.get()) != 0) {
                return application::ClientResult<std::size_t>::error(
                    application::ClientError::storage("Failed to flush file buffers during shred"));
            }
            if (options.flush_to_disk) {
                if (_commit(_fileno(fp_guard.get())) != 0) {
                    return application::ClientResult<std::size_t>::error(
                        application::ClientError::storage("Failed to commit file buffers to disk during shred"));
                }
            }
            if (options.pass_observer) {
                options.pass_observer(pass, path);
            }
        }
        fp_guard.reset();
#else
        const std::string path_str = path.string();
        PosixFdGuard fd_guard(::open(path_str.c_str(), O_RDWR));
        if (fd_guard.get() < 0) {
            return application::ClientResult<std::size_t>::error(application::ClientError::storage(
                "Failed to open file for shredding: " + std::string(std::strerror(errno))));
        }

        for (uint32_t pass = 0U; pass < passes; ++pass) {
            if (::lseek(fd_guard.get(), 0, SEEK_SET) < 0) {
                return application::ClientResult<std::size_t>::error(application::ClientError::storage(
                    "Failed to rewind file descriptor during shred: " + std::string(std::strerror(errno))));
            }
            std::size_t remaining = file_size;
            while (remaining > 0U) {
                const std::size_t to_write = std::min(remaining, buffer.size());
                const auto fill_res = fill_pass_buffer(pass, buffer, to_write);
                if (fill_res.is_error()) {
                    return application::ClientResult<std::size_t>::error(fill_res.error());
                }

                std::size_t offset = 0U;
                while (offset < to_write) {
                    const ssize_t wrote = ::write(fd_guard.get(), buffer.data() + offset, to_write - offset);
                    if (wrote < 0) {
                        if (errno == EINTR) {
                            continue;
                        }
                        return application::ClientResult<std::size_t>::error(application::ClientError::storage(
                            "Write error during forensic file shred: " + std::string(std::strerror(errno))));
                    }
                    offset += static_cast<std::size_t>(wrote);
                }

                remaining -= to_write;
                total_bytes_overwritten += to_write;
            }

            if (options.flush_to_disk) {
                if (::fsync(fd_guard.get()) != 0 && errno != EINVAL) {
                    return application::ClientResult<std::size_t>::error(application::ClientError::storage(
                        "fsync failed during forensic file shred: " + std::string(std::strerror(errno))));
                }
            }
            if (options.pass_observer) {
                options.pass_observer(pass, path);
            }
        }
        fd_guard.reset();
#endif

        std::filesystem::resize_file(path, 0U, ec);
        if (ec) {
            return application::ClientResult<std::size_t>::error(
                application::ClientError::storage("Failed to truncate shredded file to 0 bytes: " + ec.message()));
        }
    }

    const bool removed = std::filesystem::remove(path, ec);
    if (ec || !removed) {
        return application::ClientResult<std::size_t>::error(application::ClientError::storage(
            "Failed to unlink shredded file: " + (ec ? ec.message() : "unknown error")));
    }

    return application::ClientResult<std::size_t>::ok(total_bytes_overwritten);
}

application::ClientResult<ShredResult> FileShredder::shred_files(const std::vector<std::filesystem::path>& paths,
                                                                 const ShredOptions& options) {
    ShredResult result;
    std::error_code ec;
    for (const auto& path : paths) {
        if (path.empty()) {
            continue;
        }
        const bool existed = std::filesystem::exists(path, ec);
        if (ec) {
            result.failed_paths.push_back(path.string() + ": " + ec.message());
            ec.clear();
            continue;
        }
        if (!existed) {
            continue;
        }

        const auto shred_res = shred_file(path, options);
        if (shred_res.is_error()) {
            result.failed_paths.push_back(path.string() + ": " + shred_res.error().user_message());
            continue;
        }
        result.files_shredded += 1U;
        result.bytes_overwritten += shred_res.value();
    }
    return application::ClientResult<ShredResult>::ok(std::move(result));
}

application::ClientResult<ShredResult> FileShredder::shred_directory_artifacts(const std::filesystem::path& dir,
                                                                               const std::vector<std::string>& suffixes,
                                                                               const ShredOptions& options) {
    if (dir.empty()) {
        return application::ClientResult<ShredResult>::ok(ShredResult{});
    }

    std::error_code ec;
    if (!std::filesystem::exists(dir, ec)) {
        if (ec) {
            return application::ClientResult<ShredResult>::error(
                application::ClientError::storage("Failed to stat artifact directory: " + ec.message()));
        }
        return application::ClientResult<ShredResult>::ok(ShredResult{});
    }

    if (!std::filesystem::is_directory(dir, ec)) {
        return application::ClientResult<ShredResult>::error(
            application::ClientError::validation("Artifact shred target is not a directory: " + dir.string()));
    }

    std::vector<std::filesystem::path> targets;
    std::size_t scanned = 0U;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (scanned >= kMaxDirectoryEntries) {
            break;
        }
        ++scanned;

        std::error_code type_ec;
        if (!entry.is_regular_file(type_ec)) {
            continue;
        }
        const std::string filename = entry.path().filename().string();
        for (const auto& suffix : suffixes) {
            if (!suffix.empty() && ends_with(filename, suffix)) {
                targets.push_back(entry.path());
                break;
            }
        }
    }
    if (ec) {
        return application::ClientResult<ShredResult>::error(
            application::ClientError::storage("Failed while scanning artifact directory: " + ec.message()));
    }

    return shred_files(targets, options);
}

} // namespace securecloud::client::infrastructure::adapters
