#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

namespace securecloud::files {

class MemoryBufferTracker;

/// RAII reservation handle that releases its reserved memory budget upon destruction.
class MemoryBufferReservation {
  public:
    MemoryBufferReservation() noexcept = default;
    MemoryBufferReservation(std::shared_ptr<MemoryBufferTracker> tracker, size_t bytes) noexcept;
    ~MemoryBufferReservation();

    MemoryBufferReservation(const MemoryBufferReservation&) = delete;
    MemoryBufferReservation& operator=(const MemoryBufferReservation&) = delete;

    MemoryBufferReservation(MemoryBufferReservation&& other) noexcept;
    MemoryBufferReservation& operator=(MemoryBufferReservation&& other) noexcept;

    /// Explicitly releases the memory reservation before destruction.
    void release() noexcept;

    /// Bytes currently reserved by this handle.
    [[nodiscard]] size_t reserved_bytes() const noexcept;

    /// Checks if this handle holds an active reservation.
    [[nodiscard]] bool holds_reservation() const noexcept;
    explicit operator bool() const noexcept { return holds_reservation(); }

  private:
    std::shared_ptr<MemoryBufferTracker> tracker_{nullptr};
    size_t reserved_bytes_{0};
};

/// Global memory buffer tracker to enforce bounded memory allocation across streaming chunks (ADR-009, FILES-009).
class MemoryBufferTracker : public std::enable_shared_from_this<MemoryBufferTracker> {
  public:
    explicit MemoryBufferTracker(size_t max_memory_bytes);
    ~MemoryBufferTracker() = default;

    MemoryBufferTracker(const MemoryBufferTracker&) = delete;
    MemoryBufferTracker& operator=(const MemoryBufferTracker&) = delete;

    /// Factory method.
    static std::shared_ptr<MemoryBufferTracker> create(size_t max_memory_bytes);

    /// Attempts to reserve `bytes` of memory.
    /// Returns a valid MemoryBufferReservation if within budget, or an empty handle if saturated.
    [[nodiscard]] MemoryBufferReservation try_reserve(size_t bytes);

    /// Releases previously reserved bytes. Called automatically by MemoryBufferReservation.
    void release(size_t bytes) noexcept;

    /// Current reserved bytes in-flight.
    [[nodiscard]] size_t current_reserved_bytes() const noexcept;

    /// Maximum memory capacity budget.
    [[nodiscard]] size_t max_memory_bytes() const noexcept;

    /// Available unreserved memory capacity in bytes.
    [[nodiscard]] size_t available_bytes() const noexcept;

  private:
    const size_t max_memory_bytes_;

    mutable std::mutex mutex_;
    size_t current_reserved_bytes_{0};
};

/// Validates request chunk size against configured ceiling.
[[nodiscard]] bool validate_chunk_request_size(size_t chunk_bytes, size_t max_allowed_bytes,
                                              std::string& out_error_message);

/// Validates total file transfer size against configured ceiling.
[[nodiscard]] bool validate_file_transfer_size(uint64_t transfer_bytes, uint64_t max_allowed_bytes,
                                              std::string& out_error_message);

} // namespace securecloud::files
