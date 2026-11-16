#include "domain/prekey_inventory_status.hpp"

namespace securecloud::client::domain {

PrekeyInventoryStatus::PrekeyInventoryStatus(int32_t active_prekey_count, int32_t claimed_prekey_count,
                                             int32_t low_inventory_threshold,
                                             std::chrono::system_clock::time_point signed_prekey_created_at,
                                             std::chrono::seconds signed_prekey_age, bool signed_prekey_needs_rotation)
    : active_prekey_count_(active_prekey_count), claimed_prekey_count_(claimed_prekey_count),
      low_inventory_threshold_(low_inventory_threshold), signed_prekey_created_at_(signed_prekey_created_at),
      signed_prekey_age_(signed_prekey_age), signed_prekey_needs_rotation_(signed_prekey_needs_rotation) {}

bool PrekeyInventoryStatus::needs_rotation() const noexcept {
    return signed_prekey_needs_rotation_ || (signed_prekey_age_ >= PrekeyPolicy::kSignedPrekeyMaxAge);
}

bool PrekeyInventoryStatus::operator==(const PrekeyInventoryStatus& other) const noexcept {
    return active_prekey_count_ == other.active_prekey_count_ && claimed_prekey_count_ == other.claimed_prekey_count_ &&
           low_inventory_threshold_ == other.low_inventory_threshold_ &&
           signed_prekey_needs_rotation_ == other.signed_prekey_needs_rotation_ &&
           signed_prekey_age_ == other.signed_prekey_age_;
}

} // namespace securecloud::client::domain
