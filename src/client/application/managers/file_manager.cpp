#include "application/managers/file_manager.hpp"

namespace securecloud::client::application::managers {

FileManager::FileManager(interfaces::IGatewayClient& gateway, interfaces::ICryptoProvider& crypto_provider)
    : gateway_(gateway), crypto_provider_(crypto_provider) {}

ClientResult<std::string> FileManager::prepare_encrypted_upload(std::string_view local_file_path) {
    if (local_file_path.empty()) {
        return ClientResult<std::string>::error(ClientError::validation("File path cannot be empty"));
    }
    const auto probe_res = gateway_.probe_gateway("/health");
    if (probe_res.is_error()) {
        return ClientResult<std::string>::error(probe_res.error());
    }
    return ClientResult<std::string>::ok("transfer-id-001");
}

ClientResult<void> FileManager::cancel_transfer(std::string_view transfer_id) {
    if (transfer_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Transfer ID cannot be empty"));
    }
    return ClientResult<void>::ok();
}

} // namespace securecloud::client::application::managers

