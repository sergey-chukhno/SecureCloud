#include "domain/crypto/skipped_keys_store.hpp"

namespace securecloud::client::domain::crypto {

application::ClientResult<void>
SkippedKeysStore::store_key(std::span<const uint8_t> dh_pub, uint32_t message_index,
                            securecloud::common::configuration::SecretString message_key,
                            std::chrono::system_clock::time_point created_at) {
    if (dh_pub.empty() || message_key.empty()) {
        return application::ClientResult<void>::error(
            application::ClientError::crypto("Invalid empty parameters for skipped key storage"));
    }

    SkippedKeyIdentifier id{
        .dh_pub = std::vector<uint8_t>(dh_pub.begin(), dh_pub.end()),
        .message_index = message_index,
    };

    if (entries_.contains(id)) {
        return application::ClientResult<void>::ok();
    }

    if (entries_.size() >= kMaxSkippedKeys) {
        prune_expired(kDefaultTtl, created_at);
        if (entries_.size() >= kMaxSkippedKeys) {
            return application::ClientResult<void>::error(
                application::ClientError::crypto("Skipped keys store capacity exceeded (limit: 1000)"));
        }
    }

    entries_.emplace(std::move(id), SkippedKeyEntry{.message_key = std::move(message_key), .created_at = created_at});
    return application::ClientResult<void>::ok();
}

std::optional<securecloud::common::configuration::SecretString>
SkippedKeysStore::extract_and_remove(std::span<const uint8_t> dh_pub, uint32_t message_index) {
    SkippedKeyIdentifier id{
        .dh_pub = std::vector<uint8_t>(dh_pub.begin(), dh_pub.end()),
        .message_index = message_index,
    };

    auto it = entries_.find(id);
    if (it == entries_.end()) {
        return std::nullopt;
    }

    auto key = std::move(it->second.message_key);
    entries_.erase(it);
    return key;
}

bool SkippedKeysStore::has_key(std::span<const uint8_t> dh_pub, uint32_t message_index) const {
    SkippedKeyIdentifier id{
        .dh_pub = std::vector<uint8_t>(dh_pub.begin(), dh_pub.end()),
        .message_index = message_index,
    };
    return entries_.contains(id);
}

std::size_t SkippedKeysStore::size() const noexcept {
    return entries_.size();
}

bool SkippedKeysStore::empty() const noexcept {
    return entries_.empty();
}

std::size_t SkippedKeysStore::prune_expired(std::chrono::seconds max_age, std::chrono::system_clock::time_point now) {
    std::size_t count = 0;
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (now - it->second.created_at >= max_age) {
            it = entries_.erase(it);
            ++count;
        } else {
            ++it;
        }
    }
    return count;
}

void SkippedKeysStore::clear() noexcept {
    entries_.clear();
}

} // namespace securecloud::client::domain::crypto
