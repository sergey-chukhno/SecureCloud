#include "crc32c.hpp"

#include <array>

namespace securecloud::gateway::audit {

namespace {

// Lookup table for CRC32C polynomial 0x82F63B78
constexpr std::array<uint32_t, 256> generate_crc32c_table() noexcept {
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (int j = 0; j < 8; ++j) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0x82F63B78U;
            } else {
                crc >>= 1;
            }
        }
        table[i] = crc;
    }
    return table;
}

constexpr auto kCrc32cTable = generate_crc32c_table();

} // namespace

uint32_t compute_crc32c(std::span<const uint8_t> data) noexcept {
    uint32_t crc = 0xFFFFFFFFU;
    for (const uint8_t byte : data) {
        crc = kCrc32cTable[(crc ^ byte) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFU;
}

} // namespace securecloud::gateway::audit
