#include "domain/one_time_prekey_record.hpp"

#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace securecloud::client::domain {

namespace {

std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    constexpr char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const uint8_t b : bytes) {
        result.push_back(hex_chars[(b >> 4) & 0x0F]);
        result.push_back(hex_chars[b & 0x0F]);
    }
    return result;
}

} // namespace

std::string_view to_string(OneTimePrekeyStatus status) noexcept {
    switch (status) {
    case OneTimePrekeyStatus::Active:
        return "Active";
    case OneTimePrekeyStatus::Claimed:
        return "Claimed";
    case OneTimePrekeyStatus::PendingUpload:
        return "PendingUpload";
    }
    return "Unknown";
}

OneTimePrekeyRecord::OneTimePrekeyRecord(std::string id, std::vector<uint8_t> public_key, OneTimePrekeyStatus status,
                                         std::chrono::system_clock::time_point created_at)
    : id_(std::move(id)), public_key_(std::move(public_key)), status_(status), created_at_(created_at) {
    if (id_.empty()) {
        throw std::invalid_argument("OneTimePrekeyRecord: prekey ID must not be empty");
    }
    if (public_key_.size() != PrekeyPolicy::kX25519PublicKeySize) {
        throw std::invalid_argument("OneTimePrekeyRecord: public key must be exactly " +
                                    std::to_string(PrekeyPolicy::kX25519PublicKeySize) + " bytes, got " +
                                    std::to_string(public_key_.size()));
    }
}

OneTimePrekeyRecord::OneTimePrekeyRecord(uint32_t numeric_id, std::vector<uint8_t> public_key,
                                         OneTimePrekeyStatus status, std::chrono::system_clock::time_point created_at)
    : OneTimePrekeyRecord(std::to_string(numeric_id), std::move(public_key), status, created_at) {}

std::string OneTimePrekeyRecord::public_key_hex() const {
    return bytes_to_hex(public_key_);
}

bool OneTimePrekeyRecord::operator==(const OneTimePrekeyRecord& other) const noexcept {
    return id_ == other.id_ && public_key_ == other.public_key_ && status_ == other.status_;
}

} // namespace securecloud::client::domain

