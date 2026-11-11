#pragma once

#include "application/client_error.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

namespace securecloud::client::domain::crypto {

struct SkippedKeyIdentifier {
    std::vector<uint8_t> dh_pub;
    uint32_t message_index{0};

    bool operator==(const SkippedKeyIdentifier& other) const noexcept {
        return message_index == other.message_index && dh_pub == other.dh_pub;
    }
};

struct SkippedKeyIdentifierHash {
    std::size_t operator()(const SkippedKeyIdentifier& id) const noexcept {
        std::size_t h = 2166136261u;
        for (uint8_t b : id.dh_pub) {
            h ^= static_cast<std::size_t>(b);
            h *= 16777619u;
        }
        h ^= static_cast<std::size_t>(id.message_index);
        h *= 16777619u;
        return h;
    }
};

struct SkippedKeyEntry {
    securecloud::common::configuration::SecretString message_key;
    std::chrono::system_clock::time_point created_at;
};

class SkippedKeysStore {
  public:
    static constexpr std::size_t kMaxSkippedKeys = 1000;
    static constexpr std::size_t kMaxSkipGap = 2000;
    static constexpr std::chrono::hours kDefaultTtl{24 * 14}; // 14 days

    SkippedKeysStore() = default;
    ~SkippedKeysStore() = default;

    SkippedKeysStore(const SkippedKeysStore&) = default;
    SkippedKeysStore& operator=(const SkippedKeysStore&) = default;
    SkippedKeysStore(SkippedKeysStore&&) noexcept = default;
    SkippedKeysStore& operator=(SkippedKeysStore&&) noexcept = default;

    application::ClientResult<void>
    store_key(std::span<const uint8_t> dh_pub, uint32_t message_index,
              securecloud::common::configuration::SecretString message_key,
              std::chrono::system_clock::time_point created_at = std::chrono::system_clock::now());

    std::optional<securecloud::common::configuration::SecretString> extract_and_remove(std::span<const uint8_t> dh_pub,
                                                                                       uint32_t message_index);

    [[nodiscard]] bool has_key(std::span<const uint8_t> dh_pub, uint32_t message_index) const;

    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] bool empty() const noexcept;

    std::size_t prune_expired(std::chrono::seconds max_age = kDefaultTtl,
                              std::chrono::system_clock::time_point now = std::chrono::system_clock::now());

    void clear() noexcept;

    [[nodiscard]] const std::unordered_map<SkippedKeyIdentifier, SkippedKeyEntry, SkippedKeyIdentifierHash>&
    entries() const noexcept {
        return entries_;
    }

  private:
    std::unordered_map<SkippedKeyIdentifier, SkippedKeyEntry, SkippedKeyIdentifierHash> entries_;
};

} // namespace securecloud::client::domain::crypto
