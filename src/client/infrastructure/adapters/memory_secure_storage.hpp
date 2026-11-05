#pragma once

#include "application/interfaces/i_secure_storage.hpp"

#include <mutex>
#include <string>
#include <unordered_map>

namespace securecloud::client::infrastructure::adapters {

class MemorySecureStorage final : public application::interfaces::ISecureStorage {
  public:
    MemorySecureStorage() = default;
    ~MemorySecureStorage() override = default;

    application::ClientResult<void>
    store_secret(std::string_view key_id, const securecloud::common::configuration::SecretString& secret) override;
    application::ClientResult<securecloud::common::configuration::SecretString>
    get_secret(std::string_view key_id) override;
    application::ClientResult<void> delete_secret(std::string_view key_id) override;
    application::ClientResult<bool> has_secret(std::string_view key_id) override;

    void clear();

  private:
    std::mutex mutex_;
    std::unordered_map<std::string, securecloud::common::configuration::SecretString> secrets_;
};

} // namespace securecloud::client::infrastructure::adapters
