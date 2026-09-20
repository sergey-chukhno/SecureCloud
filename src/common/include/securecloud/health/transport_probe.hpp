#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>

namespace securecloud::common::health {

constexpr std::chrono::milliseconds k_default_probe_timeout{250};

[[nodiscard]] bool probe_tcp_connectivity(std::string_view host, uint16_t port,
                                          std::chrono::milliseconds timeout = k_default_probe_timeout) noexcept;

} // namespace securecloud::common::health
