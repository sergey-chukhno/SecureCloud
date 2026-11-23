#pragma once

#include "domain/one_time_prekey_record.hpp"
#include "domain/prekey_policy.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace securecloud::client::domain {

class PrekeyBundle {
  public:
    PrekeyBundle() = default;

    PrekeyBundle(std::vector<uint8_t> identity_key, std::vector<uint8_t> signed_prekey,
                 std::vector<uint8_t> signed_prekey_signature, std::vector<OneTimePrekeyRecord> one_time_prekeys = {},
                 std::chrono::system_clock::time_point created_at = std::chrono::system_clock::now());

    [[nodiscard]] const std::vector<uint8_t>& identity_key() const noexcept { return identity_key_; }
    [[nodiscard]] std::string identity_key_hex() const;

    [[nodiscard]] const std::vector<uint8_t>& signed_prekey() const noexcept { return signed_prekey_; }
    [[nodiscard]] std::string signed_prekey_hex() const;

    [[nodiscard]] const std::vector<uint8_t>& signed_prekey_signature() const noexcept {
        return signed_prekey_signature_;
    }
    [[nodiscard]] std::string signed_prekey_signature_hex() const;

    [[nodiscard]] const std::vector<OneTimePrekeyRecord>& one_time_prekeys() const noexcept {
        return one_time_prekeys_;
    }
    [[nodiscard]] std::size_t one_time_prekey_count() const noexcept { return one_time_prekeys_.size(); }
    [[nodiscard]] std::chrono::system_clock::time_point created_at() const noexcept { return created_at_; }

    void add_one_time_prekey(OneTimePrekeyRecord record);
    void set_signed_prekey(std::vector<uint8_t> signed_prekey, std::vector<uint8_t> signature);
    void clear_one_time_prekeys() noexcept { one_time_prekeys_.clear(); }

    bool operator==(const PrekeyBundle& other) const noexcept;
    bool operator!=(const PrekeyBundle& other) const noexcept { return !(*this == other); }

  private:
    std::vector<uint8_t> identity_key_;
    std::vector<uint8_t> signed_prekey_;
    std::vector<uint8_t> signed_prekey_signature_;
    std::vector<OneTimePrekeyRecord> one_time_prekeys_;
    std::chrono::system_clock::time_point created_at_{std::chrono::system_clock::now()};
};

} // namespace securecloud::client::domain
