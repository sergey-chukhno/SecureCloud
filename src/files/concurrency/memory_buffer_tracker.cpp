#include "memory_buffer_tracker.hpp"

#include <utility>

namespace securecloud::files {

MemoryBufferReservation::MemoryBufferReservation(std::shared_ptr<MemoryBufferTracker> tracker, size_t bytes) noexcept
    : tracker_(std::move(tracker)), reserved_bytes_(bytes) {}

MemoryBufferReservation::~MemoryBufferReservation() {
    release();
}

MemoryBufferReservation::MemoryBufferReservation(MemoryBufferReservation&& other) noexcept
    : tracker_(std::move(other.tracker_)), reserved_bytes_(other.reserved_bytes_) {
    other.tracker_ = nullptr;
    other.reserved_bytes_ = 0;
}

MemoryBufferReservation& MemoryBufferReservation::operator=(MemoryBufferReservation&& other) noexcept {
    if (this != &other) {
        release();
        tracker_ = std::move(other.tracker_);
        reserved_bytes_ = other.reserved_bytes_;
        other.tracker_ = nullptr;
        other.reserved_bytes_ = 0;
    }
    return *this;
}

void MemoryBufferReservation::release() noexcept {
    if (tracker_ && reserved_bytes_ > 0) {
        tracker_->release(reserved_bytes_);
        tracker_ = nullptr;
        reserved_bytes_ = 0;
    }
}

size_t MemoryBufferReservation::reserved_bytes() const noexcept {
    return reserved_bytes_;
}

bool MemoryBufferReservation::holds_reservation() const noexcept {
    return tracker_ != nullptr && reserved_bytes_ > 0;
}

MemoryBufferTracker::MemoryBufferTracker(size_t max_memory_bytes)
    : max_memory_bytes_(max_memory_bytes > 0 ? max_memory_bytes : 1) {}

std::shared_ptr<MemoryBufferTracker> MemoryBufferTracker::create(size_t max_memory_bytes) {
    return std::make_shared<MemoryBufferTracker>(max_memory_bytes);
}

MemoryBufferReservation MemoryBufferTracker::try_reserve(size_t bytes) {
    if (bytes == 0) {
        return MemoryBufferReservation();
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (current_reserved_bytes_ + bytes <= max_memory_bytes_) {
        current_reserved_bytes_ += bytes;
        return MemoryBufferReservation(shared_from_this(), bytes);
    }

    return MemoryBufferReservation();
}

void MemoryBufferTracker::release(size_t bytes) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (bytes >= current_reserved_bytes_) {
        current_reserved_bytes_ = 0;
    } else {
        current_reserved_bytes_ -= bytes;
    }
}

size_t MemoryBufferTracker::current_reserved_bytes() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_reserved_bytes_;
}

size_t MemoryBufferTracker::max_memory_bytes() const noexcept {
    return max_memory_bytes_;
}

size_t MemoryBufferTracker::available_bytes() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (current_reserved_bytes_ >= max_memory_bytes_) {
        return 0;
    }
    return max_memory_bytes_ - current_reserved_bytes_;
}

bool validate_chunk_request_size(size_t chunk_bytes, size_t max_allowed_bytes,
                                 std::string& out_error_message) {
    if (chunk_bytes == 0) {
        out_error_message = "Chunk request size cannot be zero";
        return false;
    }
    if (chunk_bytes > max_allowed_bytes) {
        out_error_message = "Chunk request size (" + std::to_string(chunk_bytes) +
                            " bytes) exceeds maximum allowed size (" +
                            std::to_string(max_allowed_bytes) + " bytes)";
        return false;
    }
    return true;
}

bool validate_file_transfer_size(uint64_t transfer_bytes, uint64_t max_allowed_bytes,
                                 std::string& out_error_message) {
    if (transfer_bytes == 0) {
        out_error_message = "File transfer size cannot be zero";
        return false;
    }
    if (transfer_bytes > max_allowed_bytes) {
        out_error_message = "File transfer size (" + std::to_string(transfer_bytes) +
                            " bytes) exceeds maximum allowed size (" +
                            std::to_string(max_allowed_bytes) + " bytes)";
        return false;
    }
    return true;
}

} // namespace securecloud::files
