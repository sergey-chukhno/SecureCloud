#pragma once

#include <string_view>

namespace securecloud::client::domain {

enum class DeliveryState { LocalPending, Submitting, Accepted, Delivering, Delivered, Read, Failed };

[[nodiscard]] std::string_view to_string(DeliveryState state) noexcept;

} // namespace securecloud::client::domain
