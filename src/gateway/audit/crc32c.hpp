#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace securecloud::gateway::audit {

/**
 * @brief Computes CRC32C (Castagnoli) checksum across a byte buffer.
 */
[[nodiscard]] uint32_t compute_crc32c(std::span<const uint8_t> data) noexcept;

} // namespace securecloud::gateway::audit
