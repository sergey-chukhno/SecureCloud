#pragma once

#include "domain/prekey_policy.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::domain {

enum class OneTimePrekeyStatus { Active, Claimed, PendingUpload };

[[nodiscard]] std::string_view to_string(OneTimePrekeyStatus status) noexcept;

class OneTimePrekeyRecord {
  public:
    OneTimePrekeyRecord(std::string id, std::vector<uint8_t> public_key,
                        OneTimePrekeyStatus status = OneTimePrekeyStatus::Active,
                        std::chrono::system_clock::time_point created_at = std::chrono::system_clock::now());

    OneTimePrekeyRecord(uint32_t numeric_id, std::vector<uint8_t> public_key,
                        OneTimePrekeyStatus status = OneTimePrekeyStatus::Active,
                        std::chrono::system_clock::time_point created_at = std::chrono::system_clock::now());

    [[nodiscard]] const std::string& id() const noexcept { return id_; }
    [[nodiscard]] const std::vector<uint8_t>& public_key() const noexcept { return public_key_; }
    [[nodiscard]] std::string public_key_hex() const;
    [[nodiscard]] OneTimePrekeyStatus status() const noexcept { return status_; }
    [[nodiscard]] std::chrono::system_clock::time_point created_at() const noexcept { return created_at_; }

    void set_status(OneTimePrekeyStatus status) noexcept { status_ = status; }

    bool operator==(const OneTimePrekeyRecord& other) const noexcept;
    bool operator!=(const OneTimePrekeyRecord& other) const noexcept { return !(*this == other); }

  private:
    std::string id_;
    std::vector<uint8_t> public_key_;
    OneTimePrekeyStatus status_{OneTimePrekeyStatus::Active};
    std::chrono::system_clock::time_point created_at_{std::chrono::system_clock::now()};
};

} // namespace securecloud::client::domain

