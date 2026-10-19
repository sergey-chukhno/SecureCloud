#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

// Forward declaration of OpenSSL structures
typedef struct evp_md_ctx_st EVP_MD_CTX;

namespace securecloud::gateway::http {

/// Stream operation status codes for bounded streaming buffer.
enum class StreamStatus {
    Ok,
    Eof,
    Closed,
    Aborted,
    Timeout,
};

/// Result of a read operation from StreamingBuffer.
struct StreamReadResult {
    StreamStatus status{StreamStatus::Ok};
    std::string data;
    size_t bytes_read{0};

    [[nodiscard]] bool ok() const noexcept { return status == StreamStatus::Ok; }
    [[nodiscard]] bool eof() const noexcept { return status == StreamStatus::Eof; }
    [[nodiscard]] bool aborted() const noexcept { return status == StreamStatus::Aborted; }
    [[nodiscard]] bool timed_out() const noexcept { return status == StreamStatus::Timeout; }
};

/// Result of a write operation to StreamingBuffer.
struct StreamWriteResult {
    StreamStatus status{StreamStatus::Ok};
    size_t bytes_written{0};

    [[nodiscard]] bool ok() const noexcept { return status == StreamStatus::Ok; }
    [[nodiscard]] bool aborted() const noexcept { return status == StreamStatus::Aborted; }
    [[nodiscard]] bool timed_out() const noexcept { return status == StreamStatus::Timeout; }
};

/// Bounded in-memory streaming buffer with backpressure signaling and activity watchdog (ADR-010, GW-010-T02).
///
/// Implements producer-consumer flow control:
/// - Producer thread blocks when buffer reaches max_buffer_bytes (propagating backpressure to transport).
/// - Consumer thread blocks when buffer is empty until data arrives or stream is closed (EOF).
/// - Tracks last_activity timestamp for watchdog idle timeout detection against slow-client/slowloris stalls.
class StreamingBuffer {
  public:
    enum class State {
        Open,
        Closed,
        Aborted,
    };

    explicit StreamingBuffer(size_t max_buffer_bytes = 8388608,
                             std::chrono::milliseconds idle_timeout = std::chrono::milliseconds(30000));
    ~StreamingBuffer();

    StreamingBuffer(const StreamingBuffer&) = delete;
    StreamingBuffer& operator=(const StreamingBuffer&) = delete;
    StreamingBuffer(StreamingBuffer&&) = delete;
    StreamingBuffer& operator=(StreamingBuffer&&) = delete;

    /// Writes data into buffer, blocking if full until consumer drains space or timeout expires.
    /// If timeout is zero, uses default idle_timeout.
    StreamWriteResult write(std::string_view data,
                            std::chrono::milliseconds timeout = std::chrono::milliseconds::zero());

    /// Reads up to max_bytes from buffer, blocking if empty until data arrives, stream closes, or timeout expires.
    /// If timeout is zero, uses default idle_timeout.
    StreamReadResult read(size_t max_bytes, std::chrono::milliseconds timeout = std::chrono::milliseconds::zero());

    /// Signals normal end-of-stream (EOF) from producer.
    /// Pending data in buffer remains readable; once drained, subsequent reads return StreamStatus::Eof.
    void close();

    /// Aborts stream immediately, unblocking all waiting readers and writers with StreamStatus::Aborted.
    void abort(std::string_view reason = "Stream aborted");

    /// Returns current buffer state.
    [[nodiscard]] State state() const;
    [[nodiscard]] bool is_open() const;
    [[nodiscard]] bool is_closed() const;
    [[nodiscard]] bool is_aborted() const;

    /// Returns abort reason string if stream was aborted.
    [[nodiscard]] std::string abort_reason() const;

    /// Returns current number of buffered bytes.
    [[nodiscard]] size_t buffered_bytes() const;

    /// Returns maximum capacity in bytes.
    [[nodiscard]] size_t max_capacity() const;

    /// Returns time elapsed since last read or write activity.
    [[nodiscard]] std::chrono::milliseconds time_since_last_activity() const;

    /// Checks if stream has stalled without I/O activity beyond threshold.
    [[nodiscard]] bool is_stalled(std::chrono::milliseconds threshold) const;

  private:
    const size_t max_capacity_;
    const std::chrono::milliseconds default_idle_timeout_;

    mutable std::mutex mutex_;
    std::condition_variable cv_readable_;
    std::condition_variable cv_writable_;

    std::deque<char> buffer_;
    State state_{State::Open};
    std::string abort_reason_;
    std::chrono::steady_clock::time_point last_activity_;
};

/// Incremental SHA-256 cryptographic streaming validator (GW-010-T02).
///
/// Computes SHA-256 digests in-flight without second-pass reads or full-file memory buffering.
/// Employs constant-time verification (CRYPTO_memcmp) to prevent timing side-channel attacks.
class StreamingSha256Validator {
  public:
    StreamingSha256Validator();
    ~StreamingSha256Validator();

    StreamingSha256Validator(const StreamingSha256Validator&) = delete;
    StreamingSha256Validator& operator=(const StreamingSha256Validator&) = delete;
    StreamingSha256Validator(StreamingSha256Validator&& other) noexcept;
    StreamingSha256Validator& operator=(StreamingSha256Validator&& other) noexcept;

    /// Feeds incremental chunk data into SHA-256 digest computation.
    void update(std::string_view data);
    void update(const void* data, size_t length);

    /// Finalizes SHA-256 computation and returns 64-character lowercase hex string.
    [[nodiscard]] std::string finalize_hex();

    /// Finalizes and compares computed digest against expected lowercase hex string in constant time.
    [[nodiscard]] bool verify(std::string_view expected_hex);

    /// Resets context to allow reusing validator for consecutive chunks.
    void reset();

    /// One-shot utility to calculate lowercase hex SHA-256 of complete buffer.
    [[nodiscard]] static std::string compute_hex(std::string_view data);

  private:
    EVP_MD_CTX* ctx_{nullptr};
    bool finalized_{false};
    std::string cached_digest_hex_;
};

} // namespace securecloud::gateway::http
