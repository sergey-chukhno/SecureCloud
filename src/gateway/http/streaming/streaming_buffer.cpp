#include "streaming_buffer.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <sstream>

namespace securecloud::gateway::http {

// =============================================================================
// StreamingBuffer Implementation
// =============================================================================

StreamingBuffer::StreamingBuffer(size_t max_buffer_bytes, std::chrono::milliseconds idle_timeout)
    : max_capacity_(max_buffer_bytes == 0 ? 8388608 : max_buffer_bytes),
      default_idle_timeout_(idle_timeout.count() == 0 ? std::chrono::milliseconds(30000) : idle_timeout),
      last_activity_(std::chrono::steady_clock::now()) {}

StreamingBuffer::~StreamingBuffer() {
    abort("StreamingBuffer destructed");
}

StreamWriteResult StreamingBuffer::write(std::string_view data, std::chrono::milliseconds timeout) {
    if (data.empty()) {
        return StreamWriteResult{.status = StreamStatus::Ok, .bytes_written = 0};
    }

    const auto wait_limit = (timeout.count() > 0) ? timeout : default_idle_timeout_;
    const auto deadline = std::chrono::steady_clock::now() + wait_limit;

    std::unique_lock<std::mutex> lock(mutex_);

    while (state_ == State::Open && (buffer_.size() + data.size() > max_capacity_)) {
        if (cv_writable_.wait_until(lock, deadline) == std::cv_status::timeout) {
            if (state_ == State::Aborted) {
                return StreamWriteResult{.status = StreamStatus::Aborted, .bytes_written = 0};
            }
            if (buffer_.size() + data.size() > max_capacity_) {
                return StreamWriteResult{.status = StreamStatus::Timeout, .bytes_written = 0};
            }
        }
    }

    if (state_ == State::Aborted) {
        return StreamWriteResult{.status = StreamStatus::Aborted, .bytes_written = 0};
    }

    if (state_ == State::Closed) {
        return StreamWriteResult{.status = StreamStatus::Closed, .bytes_written = 0};
    }

    buffer_.insert(buffer_.end(), data.begin(), data.end());
    last_activity_ = std::chrono::steady_clock::now();

    cv_readable_.notify_one();
    return StreamWriteResult{.status = StreamStatus::Ok, .bytes_written = data.size()};
}

StreamReadResult StreamingBuffer::read(size_t max_bytes, std::chrono::milliseconds timeout) {
    if (max_bytes == 0) {
        return StreamReadResult{.status = StreamStatus::Ok, .data = "", .bytes_read = 0};
    }

    const auto wait_limit = (timeout.count() > 0) ? timeout : default_idle_timeout_;
    const auto deadline = std::chrono::steady_clock::now() + wait_limit;

    std::unique_lock<std::mutex> lock(mutex_);

    while (state_ == State::Open && buffer_.empty()) {
        if (cv_readable_.wait_until(lock, deadline) == std::cv_status::timeout) {
            if (state_ == State::Aborted) {
                return StreamReadResult{.status = StreamStatus::Aborted, .data = "", .bytes_read = 0};
            }
            if (buffer_.empty() && state_ == State::Open) {
                return StreamReadResult{.status = StreamStatus::Timeout, .data = "", .bytes_read = 0};
            }
        }
    }

    if (state_ == State::Aborted && buffer_.empty()) {
        return StreamReadResult{.status = StreamStatus::Aborted, .data = "", .bytes_read = 0};
    }

    if (buffer_.empty() && state_ == State::Closed) {
        return StreamReadResult{.status = StreamStatus::Eof, .data = "", .bytes_read = 0};
    }

    const size_t to_read = std::min(max_bytes, buffer_.size());
    std::string out_data;
    out_data.resize(to_read);

    for (size_t i = 0; i < to_read; ++i) {
        out_data[i] = buffer_.front();
        buffer_.pop_front();
    }

    last_activity_ = std::chrono::steady_clock::now();
    cv_writable_.notify_one();

    return StreamReadResult{.status = StreamStatus::Ok, .data = std::move(out_data), .bytes_read = to_read};
}

void StreamingBuffer::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == State::Open) {
        state_ = State::Closed;
    }
    cv_readable_.notify_all();
    cv_writable_.notify_all();
}

void StreamingBuffer::abort(std::string_view reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != State::Aborted) {
        state_ = State::Aborted;
        abort_reason_ = reason.empty() ? "Stream aborted" : std::string(reason);
        buffer_.clear();
    }
    cv_readable_.notify_all();
    cv_writable_.notify_all();
}

StreamingBuffer::State StreamingBuffer::state() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_;
}

bool StreamingBuffer::is_open() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_ == State::Open;
}

bool StreamingBuffer::is_closed() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_ == State::Closed;
}

bool StreamingBuffer::is_aborted() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_ == State::Aborted;
}

std::string StreamingBuffer::abort_reason() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return abort_reason_;
}

size_t StreamingBuffer::buffered_bytes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return buffer_.size();
}

size_t StreamingBuffer::max_capacity() const {
    return max_capacity_;
}

std::chrono::milliseconds StreamingBuffer::time_since_last_activity() const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now - last_activity_);
}

bool StreamingBuffer::is_stalled(std::chrono::milliseconds threshold) const {
    return time_since_last_activity() >= threshold;
}

// =============================================================================
// StreamingSha256Validator Implementation
// =============================================================================

namespace {

std::string to_hex_string(const unsigned char* data, size_t length) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        oss << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    return oss.str();
}

} // namespace

StreamingSha256Validator::StreamingSha256Validator() {
    ctx_ = EVP_MD_CTX_new();
    if (ctx_) {
        EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr);
    }
}

StreamingSha256Validator::~StreamingSha256Validator() {
    if (ctx_) {
        EVP_MD_CTX_free(ctx_);
        ctx_ = nullptr;
    }
}

StreamingSha256Validator::StreamingSha256Validator(StreamingSha256Validator&& other) noexcept
    : ctx_(other.ctx_), finalized_(other.finalized_), cached_digest_hex_(std::move(other.cached_digest_hex_)) {
    other.ctx_ = nullptr;
    other.finalized_ = false;
}

StreamingSha256Validator& StreamingSha256Validator::operator=(StreamingSha256Validator&& other) noexcept {
    if (this != &other) {
        if (ctx_) {
            EVP_MD_CTX_free(ctx_);
        }
        ctx_ = other.ctx_;
        finalized_ = other.finalized_;
        cached_digest_hex_ = std::move(other.cached_digest_hex_);
        other.ctx_ = nullptr;
        other.finalized_ = false;
    }
    return *this;
}

void StreamingSha256Validator::update(std::string_view data) {
    update(data.data(), data.size());
}

void StreamingSha256Validator::update(const void* data, size_t length) {
    if (!ctx_ || finalized_ || data == nullptr || length == 0) {
        return;
    }
    EVP_DigestUpdate(ctx_, data, length);
}

std::string StreamingSha256Validator::finalize_hex() {
    if (finalized_) {
        return cached_digest_hex_;
    }
    if (!ctx_) {
        return "";
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> hash_buf{};
    unsigned int hash_len = 0;

    if (EVP_DigestFinal_ex(ctx_, hash_buf.data(), &hash_len) == 1) {
        cached_digest_hex_ = to_hex_string(hash_buf.data(), hash_len);
    } else {
        cached_digest_hex_.clear();
    }

    finalized_ = true;
    return cached_digest_hex_;
}

bool StreamingSha256Validator::verify(std::string_view expected_hex) {
    const std::string computed = finalize_hex();
    if (computed.size() != expected_hex.size() || computed.empty()) {
        return false;
    }

    std::string expected_norm(expected_hex);
    for (char& c : expected_norm) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    return CRYPTO_memcmp(computed.data(), expected_norm.data(), computed.size()) == 0;
}

void StreamingSha256Validator::reset() {
    finalized_ = false;
    cached_digest_hex_.clear();
    if (ctx_) {
        EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr);
    }
}

std::string StreamingSha256Validator::compute_hex(std::string_view data) {
    StreamingSha256Validator val;
    val.update(data);
    return val.finalize_hex();
}

} // namespace securecloud::gateway::http
