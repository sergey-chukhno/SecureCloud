#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "application/interfaces/i_gateway_client.hpp"

#include <string>
#include <string_view>

namespace securecloud::client::application::managers {

class FileManager {
  public:
    FileManager(interfaces::IGatewayClient& gateway, interfaces::ICryptoProvider& crypto_provider);
    ~FileManager() = default;

    FileManager(const FileManager&) = delete;
    FileManager& operator=(const FileManager&) = delete;

    ClientResult<std::string> prepare_encrypted_upload(std::string_view local_file_path);
    ClientResult<void> cancel_transfer(std::string_view transfer_id);

    [[nodiscard]] interfaces::ICryptoProvider& crypto_provider() noexcept { return crypto_provider_; }

  private:
    interfaces::IGatewayClient& gateway_;
    interfaces::ICryptoProvider& crypto_provider_;
};

} // namespace securecloud::client::application::managers
