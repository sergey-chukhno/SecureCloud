#pragma once

#include "domain/prekey_policy.hpp"

#include <chrono>
#include <cstdint>

namespace securecloud::client::domain {

class PrekeyInventoryStatus {
  public:
    PrekeyInventoryStatus() = default;

    PrekeyInventoryStatus(
        int32_t active_prekey_count, int32_t claimed_prekey_count,
        int32_t low_inventory_threshold = static_cast<int32_t>(PrekeyPolicy::kLowPrekeyThreshold),
        std::chrono::system_clock::time_point signed_prekey_created_at = std::chrono::system_clock::now(),
        std::chrono::seconds signed_prekey_age = std::chrono::seconds(0), bool signed_prekey_needs_rotation = false);

    [[nodiscard]] int32_t active_prekey_count() const noexcept { return active_prekey_count_; }
    [[nodiscard]] int32_t claimed_prekey_count() const noexcept { return claimed_prekey_count_; }
    [[nodiscard]] int32_t total_prekey_count() const noexcept { return active_prekey_count_ + claimed_prekey_count_; }
    [[nodiscard]] int32_t low_inventory_threshold() const noexcept { return low_inventory_threshold_; }

    [[nodiscard]] bool is_low_inventory() const noexcept { return active_prekey_count_ <= low_inventory_threshold_; }
    [[nodiscard]] bool is_exhausted() const noexcept { return active_prekey_count_ <= 0; }
    [[nodiscard]] bool needs_replenishment() const noexcept { return is_low_inventory(); }

    [[nodiscard]] std::chrono::system_clock::time_point signed_prekey_created_at() const noexcept {
        return signed_prekey_created_at_;
    }
    [[nodiscard]] std::chrono::seconds signed_prekey_age() const noexcept { return signed_prekey_age_; }
    [[nodiscard]] bool signed_prekey_needs_rotation() const noexcept { return signed_prekey_needs_rotation_; }
    [[nodiscard]] bool needs_rotation() const noexcept;

    void set_active_prekey_count(int32_t count) noexcept { active_prekey_count_ = count; }
    void set_claimed_prekey_count(int32_t count) noexcept { claimed_prekey_count_ = count; }
    void set_signed_prekey_needs_rotation(bool needs_rot) noexcept { signed_prekey_needs_rotation_ = needs_rot; }
    void set_signed_prekey_age(std::chrono::seconds age) noexcept { signed_prekey_age_ = age; }

    bool operator==(const PrekeyInventoryStatus& other) const noexcept;
    bool operator!=(const PrekeyInventoryStatus& other) const noexcept { return !(*this == other); }

  private:
    int32_t active_prekey_count_{0};
    int32_t claimed_prekey_count_{0};
    int32_t low_inventory_threshold_{static_cast<int32_t>(PrekeyPolicy::kLowPrekeyThreshold)};
    std::chrono::system_clock::time_point signed_prekey_created_at_{std::chrono::system_clock::now()};
    std::chrono::seconds signed_prekey_age_{0};
    bool signed_prekey_needs_rotation_{false};
};

} // namespace securecloud::client::domain

