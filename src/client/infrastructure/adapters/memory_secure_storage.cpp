#include "infrastructure/adapters/memory_secure_storage.hpp"

#include <algorithm>

namespace securecloud::client::infrastructure::adapters {

application::ClientResult<void>
MemorySecureStorage::store_secret(std::string_view key_id,
                                  const securecloud::common::configuration::SecretString& secret) {
    if (key_id.empty()) {
        return application::ClientResult<void>::error(application::ClientError::validation("Key ID cannot be empty"));
    }
    std::lock_guard<std::mutex> lock(mutex_);
    secrets_[std::string(key_id)] = secret;
    return application::ClientResult<void>::ok();
}

application::ClientResult<securecloud::common::configuration::SecretString>
MemorySecureStorage::get_secret(std::string_view key_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = secrets_.find(std::string(key_id));
    if (it == secrets_.end()) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::storage("Secret not found"));
    }
    return application::ClientResult<securecloud::common::configuration::SecretString>::ok(it->second);
}

application::ClientResult<void> MemorySecureStorage::delete_secret(std::string_view key_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    secrets_.erase(std::string(key_id));
    return application::ClientResult<void>::ok();
}

application::ClientResult<bool> MemorySecureStorage::has_secret(std::string_view key_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    return application::ClientResult<bool>::ok(secrets_.find(std::string(key_id)) != secrets_.end());
}

application::ClientResult<std::vector<std::string>> MemorySecureStorage::list_secret_keys() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> keys;
    keys.reserve(secrets_.size());
    for (const auto& [key, _] : secrets_) {
        keys.push_back(key);
    }
    std::sort(keys.begin(), keys.end());
    return application::ClientResult<std::vector<std::string>>::ok(std::move(keys));
}

application::ClientResult<std::size_t> MemorySecureStorage::purge_all_secrets() {
    std::lock_guard<std::mutex> lock(mutex_);
    const std::size_t purged_count = secrets_.size();
    for (auto& [_, secret] : secrets_) {
        secret = securecloud::common::configuration::SecretString{};
    }
    secrets_.clear();
    return application::ClientResult<std::size_t>::ok(purged_count);
}

void MemorySecureStorage::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [_, secret] : secrets_) {
        secret = securecloud::common::configuration::SecretString{};
    }
    secrets_.clear();
}

} // namespace securecloud::client::infrastructure::adapters
